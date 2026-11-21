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
//!
//! Arithmetic is checked end to end: a weighted sum, credit total or rounded
//! value that would leave the finite `f64` domain is refused as
//! `invalid_input` instead of being published as `inf`/`NaN`. One course name
//! identifies one course inside one selection, so a repeated name is refused
//! whether it repeats the same values or conflicting ones: summing it would
//! double-weight the credits and keeping either value would drop supplied
//! data. A score the declared policy carries no point for is refused, never
//! scored as a guessed `0.0`.
//!
//! GPA and baseline-save input accept exactly one of `courses` or
//! `marks_session`, alongside `policy`. `marks_session` is the complete parsed
//! output of `marks session`: KCMC/CJ/XF supply name/integer score/credit.
//! Numeric grade strings may have only zero fractional digits; qualitative,
//! pending and fractional grades are refused without rounding or conversion.
//! The session's requested_xnxqdm is retained in calculations and baselines.
//! When both sides of a diff supply a term scope, those scopes must match.

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

mod session;
pub use session::session;

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_PATH: usize = 4096;
// Half of f64::MAX/10,000, so round4 scaling remains finite with margin.
const MAX_SAFE_CREDIT_TOTAL: f64 = f64::MAX / 20_000.0;
const DEFAULT_PASS_MIN: u8 = 60;
const MAX_BASELINE_BYTES: u64 = MAX_POLICY_BYTES * 4;
// Ownership-policy refusals: the supplied value is well formed, but the
// filesystem state violates the published baseline path policy.
const UNSAFE_PARENT: &str =
    "baseline parent directory must be owner-controlled and free of symlinks";
const UNSAFE_FILE: &str = "baseline file must be a regular owner-controlled file with mode 0600";

fn invalid() -> Value {
    json!({"error":"invalid_input","message":"marks input is invalid"})
}

fn unavailable(message: &'static str) -> Value {
    json!({"error":"unavailable","message":message})
}

fn permission(message: &'static str) -> Value {
    json!({"error":"permission","message":message})
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
    fn point_for(&self, score: u8) -> Option<f64> {
        match &self.policy {
            Policy::Table(bands, pass_min) => {
                if score < *pass_min {
                    return Some(0.0);
                }
                // A table validated to cover [pass_min, 100] always matches.
                // A miss is an unsupported score under the declared policy,
                // so it is refused instead of being guessed as 0.0.
                bands
                    .iter()
                    .find(|band| score >= band.min && score <= band.max)
                    .map(|band| band.point)
            }
            Policy::Formula { a, b, c, .. } => {
                let x = f64::from(100u8) - f64::from(score);
                let point = (a - b * x * x / c).clamp(0.0, *a);
                point.is_finite().then_some(point)
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
    // Only the two published policy kinds are supported. An unknown or missing
    // `kind` is refused explicitly rather than coerced into a default scoring
    // shape.
    if !matches!(
        raw.get("policy")
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str),
        Some("table" | "formula")
    ) {
        return Err(json!({
            "error":"invalid_input",
            "message":"unsupported policy kind; expected table or formula"
        }));
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
                // `!(range.contains)` also refuses NaN, which two separate
                // `< 0.0` / `> 5.0` comparisons would silently admit.
                if band.min > band.max || band.max > 100 || !(0.0..=5.0).contains(&band.point) {
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

const MAX_SESSION_ROWS: u64 = 512;
const SESSION_TERM_PATTERN: &str = "^[0-9]{4}[123]$";

fn session_records(session: &Value) -> Result<&[Value], Value> {
    let records = session
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let completeness = &session["completeness"];
    if session.get("schema_version").and_then(Value::as_u64) != Some(1)
        || session.get("type").and_then(Value::as_str) != Some("marks_gsmis")
        || session.get("result").and_then(Value::as_str) != Some("parsed")
        || completeness.get("complete").and_then(Value::as_bool) != Some(true)
        || !completeness
            .get("reasons")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        || records.len() as u64 > MAX_SESSION_ROWS
        || session.get("unscoped_term_row_count").and_then(Value::as_u64) != Some(0)
        || session.get("requested_term_match_count").and_then(Value::as_u64)
            != Some(records.len() as u64)
    {
        return Err(invalid());
    }
    let term = match session.get("requested_xnxqdm") {
        Some(Value::Null) => None,
        Some(Value::String(term)) if crate::timetable::valid_term_code(term) => Some(term.as_str()),
        _ => return Err(invalid()),
    };
    let source_count = session
        .get("source_row_count")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    let other_count = session
        .get("other_term_count")
        .and_then(Value::as_u64)
        .ok_or_else(invalid)?;
    if source_count > MAX_SESSION_ROWS
        || source_count.checked_sub(other_count) != Some(records.len() as u64)
        || session.get("declared_total").and_then(Value::as_u64) != Some(source_count)
        || (term.is_none() && other_count != 0)
    {
        return Err(invalid());
    }
    if let Some(term) = term {
        for row in records {
            if row.get("XNXQDM").and_then(Value::as_str) != Some(term) {
                return Err(invalid());
            }
        }
    }
    Ok(records)
}

fn session_course(row: &Value) -> Result<CourseInput, Value> {
    // Canonical GPA fields beside source fields would supply two identities
    // for the same fact; refuse rather than choose one silently.
    if ["name", "score", "credit"]
        .into_iter()
        .any(|key| row.get(key).is_some())
    {
        return Err(invalid());
    }
    let name = row
        .get("KCMC")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(invalid)?;
    let grade = row.get("CJ").ok_or_else(invalid)?;
    let score = if let Some(score) = grade.as_u64() {
        u8::try_from(score).map_err(|_| invalid())?
    } else if let Some(text) = grade.as_str() {
        let text = text.trim();
        let (whole, fraction) = text.split_once('.').unwrap_or((text, "0"));
        if whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_empty()
            || !fraction.bytes().all(|byte| byte == b'0')
        {
            return Err(invalid());
        }
        whole.parse::<u8>().map_err(|_| invalid())?
    } else {
        // Float JSON grades are not rounded or cast into integer bands.
        return Err(invalid());
    };
    let credit = match row.get("XF") {
        Some(Value::String(text)) => text.trim().parse::<f64>().map_err(|_| invalid())?,
        Some(value) => value.as_f64().ok_or_else(invalid)?,
        None => return Err(invalid()),
    };
    Ok(CourseInput {
        name: name.to_owned(),
        score,
        credit,
    })
}

fn parse_courses(raw: &Value) -> Result<Vec<Course>, Value> {
    let (list, from_session) = match (raw.get("courses"), raw.get("marks_session")) {
        (Some(Value::Array(list)), None) => (list.as_slice(), false),
        (None, Some(session)) => (session_records(session)?, true),
        _ => return Err(invalid()),
    };
    if list.len() > 10_000 {
        return Err(invalid());
    }
    let mut seen: BTreeMap<String, (u8, f64)> = BTreeMap::new();
    let mut courses = Vec::with_capacity(list.len());
    let mut total_credit = 0.0;
    for item in list {
        let input = if from_session {
            session_course(item)?
        } else {
            serde_json::from_value::<CourseInput>(item.clone()).map_err(|_| invalid())?
        };
        if input.name.is_empty()
            || input.score > 100
            || !input.credit.is_finite()
            || input.credit <= 0.0
            || input.credit >= MAX_SAFE_CREDIT_TOTAL
        {
            return Err(invalid());
        }
        let next_total = total_credit + input.credit;
        if !next_total.is_finite() || next_total >= MAX_SAFE_CREDIT_TOTAL {
            return Err(invalid());
        }
        total_credit = next_total;
        if let Some((seen_score, seen_credit)) =
            seen.insert(input.name.clone(), (input.score, input.credit))
        {
            // One name is one course inside one selection. The repeat is
            // refused either way: summing it double-weights the credits and
            // keeping one row would drop supplied data. Conflicting values are
            // named as such so the caller can fix the real defect.
            let conflict = seen_score != input.score || seen_credit != input.credit;
            let message = if conflict {
                "conflicting duplicate course name in selection"
            } else {
                "duplicate course name in selection"
            };
            return Err(json!({"error":"invalid_input","message":message}));
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
    let mut seen: BTreeMap<String, (u8, f64)> = BTreeMap::new();
    let mut courses = Vec::with_capacity(list.len());
    let mut total_credit = 0.0;
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
        let score = score as u8;
        let credit = item
            .get("credit")
            .and_then(Value::as_f64)
            .filter(|credit| credit.is_finite() && *credit > 0.0 && *credit < MAX_SAFE_CREDIT_TOTAL)
            .ok_or_else(
                || json!({"error":"invalid_input","message":"baseline courses are malformed"}),
            )?;
        let next_total = total_credit + credit;
        if !next_total.is_finite() || next_total >= MAX_SAFE_CREDIT_TOTAL {
            return Err(
                json!({"error":"invalid_input","message":"baseline courses are malformed"}),
            );
        }
        total_credit = next_total;
        if let Some((seen_score, seen_credit)) = seen.insert(name.clone(), (score, credit)) {
            let conflict = seen_score != score || seen_credit != credit;
            let message = if conflict {
                "conflicting duplicate course name in baseline"
            } else {
                "duplicate course name in baseline"
            };
            return Err(json!({"error":"invalid_input","message":message}));
        }
        courses.push(Course {
            name,
            score,
            credit,
        });
    }
    Ok(courses)
}

/// Checked `f64` accumulation: a non-finite term or sum is refused, so a
/// published credit total or weighted sum can never become `inf`/`NaN`.
fn checked_sum(total: f64, term: f64) -> Option<f64> {
    if !total.is_finite() || !term.is_finite() {
        return None;
    }
    let sum = total + term;
    sum.is_finite().then_some(sum)
}

/// Checked `round4`: the 10^4 scaling is refused when it would leave the
/// finite domain, so no published number can be `inf`.
fn round4(value: f64) -> Option<f64> {
    let scaled = value * 10_000.0;
    if !scaled.is_finite() {
        return None;
    }
    Some(scaled.round() / 10_000.0)
}

#[derive(Debug, Clone)]
struct Calculation {
    gpa: Option<f64>,
    counted_credits: f64,
    total_credits: f64,
    lines: Vec<Value>,
}

fn compute(context: &PolicyContext, courses: &[Course]) -> Result<Calculation, Value> {
    let pass_min = context.pass_min();
    let mut numerator = 0.0;
    let mut counted_credits = 0.0;
    let mut total_credits = 0.0;
    let mut lines = Vec::with_capacity(courses.len());
    for course in courses {
        // `compute` is the last boundary before arithmetic, so it re-checks the
        // course domain instead of trusting every caller to have validated it.
        if course.score > 100 || !course.credit.is_finite() || course.credit <= 0.0 {
            return Err(invalid());
        }
        let pass = course.score >= pass_min;
        let point = if pass {
            context.point_for(course.score).ok_or_else(invalid)?
        } else {
            0.0
        };
        if pass {
            numerator = checked_sum(numerator, point * course.credit).ok_or_else(invalid)?;
            counted_credits = checked_sum(counted_credits, course.credit).ok_or_else(invalid)?;
        }
        total_credits = checked_sum(total_credits, course.credit).ok_or_else(invalid)?;
        let shown_point = round4(point).ok_or_else(invalid)?;
        lines.push(json!({
            "name": course.name,
            "score": course.score,
            "credit": course.credit,
            "point": shown_point,
            "counts": pass
        }));
    }
    let gpa = if counted_credits > 0.0 {
        let mean = numerator / counted_credits;
        if !mean.is_finite() || mean < 0.0 {
            return Err(invalid());
        }
        Some(round4(mean).ok_or_else(invalid)?)
    } else {
        None
    };
    Ok(Calculation {
        gpa,
        counted_credits: round4(counted_credits).ok_or_else(invalid)?,
        total_credits: round4(total_credits).ok_or_else(invalid)?,
        lines,
    })
}

fn policy_provenance(context: &PolicyContext) -> Value {
    json!({"id": context.id, "source": context.source, "policy": context.as_value()})
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Compute GPA from a policy and either `courses` or a complete
/// `marks_session` result, with an optional baseline for the structured diff.
pub fn gpa(input: &str) -> Value {
    if input.len() as u64 > MAX_POLICY_BYTES {
        return invalid();
    }
    let raw: crate::timetable::PrivateValue = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return invalid(),
    };
    let (context, courses, current) = match load_current(&raw) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let mut out = json!({
        "schema_version": 1,
        "type": "gpa_calculation",
        "policy": policy_provenance(&context),
        "courses": current.lines,
        "counted_credits": current.counted_credits,
        "total_credits": current.total_credits,
        "gpa": current.gpa,
    });
    let requested_term = raw.pointer("/marks_session/requested_xnxqdm");
    if let Some(term) = requested_term {
        out["requested_xnxqdm"] = term.clone();
    }
    if let Some(baseline) = raw.get("baseline") {
        if let (Some(current_term), Some(baseline_term)) =
            (requested_term, baseline.get("requested_xnxqdm"))
        {
            if current_term != baseline_term {
                return json!({"error":"invalid_input","message":"baseline requested term scope does not match current marks session"});
            }
        }
        let difference = diff_value(baseline, &current, &context, &courses);
        if difference.get("error").is_some() {
            return difference;
        }
        out["diff"] = difference;
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
            // No defaulting: the canonical content this tool emits always
            // carries pass_min, so an absent bound must fail the comparison
            // rather than be guessed as the default and silently match.
            let pass_min = value.get("pass_min").and_then(Value::as_u64)?;
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
            "pass_min":value.get("pass_min").and_then(Value::as_u64)?,
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
    let baseline_calc = match compute(context, &baseline_courses) {
        Ok(value) => value,
        Err(_) => {
            return json!({"error":"invalid_input","message":"baseline courses are malformed"});
        }
    };

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
        (Some(before), Some(after)) => round4(after - before),
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
fn baseline_location(path: &Path) -> Result<(File, String), Value> {
    let Some(name) = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
    else {
        return Err(invalid());
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("/"));
    let directory = crate::governor::open_directory(parent, false, false).map_err(|error| {
        match error.as_str() {
            "governor directory ownership or permissions are unsafe" => permission(UNSAFE_PARENT),
            _ => invalid(),
        }
    })?;
    Ok((directory, name.to_owned()))
}

fn read_private_baseline(directory: &File, name: &str) -> Result<Option<String>, Value> {
    let file = match crate::governor::open_child(directory, name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
    };
    crate::governor::validate_private_file(&file).map_err(|error| match error.as_str() {
        "governor file ownership or permissions are unsafe" => permission(UNSAFE_FILE),
        _ => invalid(),
    })?;
    let mut text = String::new();
    file.take(MAX_BASELINE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| invalid())?;
    if text.len() as u64 > MAX_BASELINE_BYTES {
        return Err(invalid());
    }
    Ok(Some(text))
}

fn save_private_baseline(directory: &File, name: &str, body: &[u8]) -> Result<(), Value> {
    let (temporary_name, mut temporary) = crate::governor::create_temporary(directory)
        .map_err(|_| unavailable("baseline could not be written"))?;
    let result = (|| {
        crate::governor::validate_private_file(&temporary)
            .map_err(|_| unavailable("baseline could not be written"))?;
        temporary
            .write_all(body)
            .map_err(|_| unavailable("baseline could not be written"))?;
        temporary
            .sync_all()
            .map_err(|_| unavailable("baseline could not be written"))?;
        let target_name = CString::new(name).map_err(|_| invalid())?;
        // SAFETY: both names are validated single components in the pinned directory.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary_name.as_ptr(),
                directory.as_raw_fd(),
                target_name.as_ptr(),
            )
        } != 0
        {
            return Err(unavailable("baseline could not be written"));
        }
        directory
            .sync_all()
            .map_err(|_| unavailable("baseline could not be written"))
    })();
    if result.is_err() {
        // SAFETY: the temporary name was created in this pinned directory.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
    }
    result
}

fn load_current(raw: &Value) -> Result<(PolicyContext, Vec<Course>, Calculation), Value> {
    let context = parse_policy(raw)?;
    let courses = parse_courses(raw)?;
    let calculation = compute(&context, &courses)?;
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
    let raw: crate::timetable::PrivateValue = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(_) => return invalid(),
    };
    let (context, courses, calc) = match load_current(&raw) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let mut document = baseline_document(&context, &calc);
    if let Some(term) = raw.pointer("/marks_session/requested_xnxqdm") {
        document["requested_xnxqdm"] = term.clone();
    }
    let (directory, name) = match baseline_location(&path) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let existing = match read_private_baseline(&directory, &name) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let unchanged = existing
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
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
    let mut body = match serde_json::to_vec(&document) {
        Ok(value) => value,
        Err(_) => return unavailable("baseline could not be serialized"),
    };
    body.push(b'\n');
    if body.len() as u64 > MAX_BASELINE_BYTES {
        return invalid();
    }
    if let Err(error) = save_private_baseline(&directory, &name, &body) {
        return error;
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
    let (directory, name) = match baseline_location(&path) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let text = match read_private_baseline(&directory, &name) {
        Ok(Some(value)) => value,
        Ok(None) => return unavailable("baseline file is not readable"),
        Err(value) => return value,
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
    let session_term = json!({"type":["string","null"],"pattern":SESSION_TERM_PATTERN});
    let marks_session = json!({
        "type":"object",
        "description":"Complete marks session output. Source and projected counts must reconcile, and a requested term must match every projected XNXQDM. Null means no term filter. KCMC, CJ and XF map to name, score and credit under the same duplicate-name and credit bounds as courses.",
        "required":["schema_version","type","result","requested_xnxqdm","records","source_row_count","requested_term_match_count","other_term_count","unscoped_term_row_count","declared_total","completeness"],
        "properties":{
            "schema_version":{"const":1},
            "type":{"const":"marks_gsmis"},
            "result":{"const":"parsed"},
            "requested_xnxqdm":session_term,
            "records":{"type":"array","maxItems":MAX_SESSION_ROWS,"items":{
                "type":"object","required":["KCMC","CJ","XF"],
                "properties":{
                    "KCMC":{"type":"string","minLength":1},
                    "CJ":{"description":"Score 0 through 100 as a JSON integer token or a decimal string with only zero fractional digits. Fractional, qualitative and pending grades are invalid.","oneOf":[
                        {"type":"integer","minimum":0,"maximum":100},
                        {"type":"string","pattern":"^\\s*[0-9]+(\\.0+)?\\s*$"}
                    ]},
                    "XF":{"description":"Positive, finite credit.","type":["number","string"]}
                }
            }},
            "source_row_count":{"type":"integer","minimum":0,"maximum":MAX_SESSION_ROWS},
            "requested_term_match_count":{"type":"integer","minimum":0,"maximum":MAX_SESSION_ROWS},
            "other_term_count":{"type":"integer","minimum":0,"maximum":MAX_SESSION_ROWS},
            "unscoped_term_row_count":{"const":0},
            "declared_total":{"type":"integer","minimum":0,"maximum":MAX_SESSION_ROWS},
            "completeness":{"type":"object","required":["complete","reasons"],"properties":{
                "complete":{"const":true},"reasons":{"type":"array","maxItems":0}
            }}
        }
    });
    json!({"gpa": {
        "input": {"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["policy"],
            "oneOf":[{"required":["courses"]},{"required":["marks_session"]}],
            "properties":{
                "policy":{"type":"object","required":["kind","id","source"],
                    "additionalProperties":false,
                    "oneOf":[
                        {"properties":{"kind":{"const":"table"}},"required":["bands"],"not":{"anyOf":[{"required":["a"]},{"required":["b"]},{"required":["c"]}]}},
                        {"properties":{"kind":{"const":"formula"}},"required":["a","b","c"],"not":{"required":["bands"]}}
                    ],
                    "properties":{"id":{"type":"string","minLength":1},
                        "source":{"type":"string","minLength":1},
                        "kind":{"enum":["table","formula"]},
                        "pass_min":{"type":"integer","minimum":0,"maximum":100,"default":DEFAULT_PASS_MIN},
                        "bands":{"type":"array","minItems":1,"description":"After sorting by min, inclusive integer bands must cover every score from pass_min (default 60) through 100 exactly once, with no gaps or overlaps; each min must be <= max. Input order need not be sorted.","items":{"type":"object","additionalProperties":false,"required":["min","max","point"],"properties":{"min":{"type":"integer","minimum":0,"maximum":100},"max":{"type":"integer","minimum":0,"maximum":100},"point":{"type":"number","minimum":0,"maximum":5}}}},
                        "a":{"type":"number","exclusiveMinimum":0,"maximum":5},"b":{"type":"number","exclusiveMinimum":0},"c":{"type":"number","exclusiveMinimum":0}},
                    "description":"Caller-supplied published policy with nonempty id/source provenance. Formula points are clamp(a - b * (100-score)^2 / c, 0, a); scores below pass_min do not count. All coefficients must be finite."},
                "courses":{"type":"array","maxItems":10000,"x-maxTotalCredit":MAX_SAFE_CREDIT_TOTAL,"description":"Course names must be unique: a repeated name is invalid_input whether it repeats identical values or conflicting score/credit values. Each credit and the aggregate credit total must be finite, positive per course, and strictly below x-maxTotalCredit.","items":{"type":"object","additionalProperties":false,"required":["name","score","credit"],
                    "properties":{"name":{"type":"string","minLength":1},
                        "score":{"type":"integer","minimum":0,"maximum":100},
                        "credit":{"type":"number","exclusiveMinimum":0,"exclusiveMaximum":MAX_SAFE_CREDIT_TOTAL}}}},
                "marks_session":marks_session,
                "baseline":{"type":"object","description":"Optional gpa_baseline document for either input form. Policy ID and normalized policy content must match. If both current input and baseline supply a requested_xnxqdm scope, those scopes must match."}}},
        "output": {"type":"object","required":["schema_version","type","policy","courses","counted_credits","total_credits","gpa"],
            "properties":{"counted_credits":{"type":"number","minimum":0,"exclusiveMaximum":MAX_SAFE_CREDIT_TOTAL},
                "total_credits":{"type":"number","minimum":0,"exclusiveMaximum":MAX_SAFE_CREDIT_TOTAL},
                "gpa":{"type":["number","null"],"minimum":0,"maximum":5},
                "requested_xnxqdm":session_term,
                "diff":{"type":"object","required":["added","removed","changed","gpa"]}}},
        "policy_provenance":"every result carries the published policy id/source; no policy is embedded in the repository"
    },
    "baseline": {
        "operations": ["save <absolute-path>", "show <absolute-path>"],
        "path_policy": "parent must already exist, be owned by the current user and not group/other writable; symlink path components are rejected; baseline files must be regular owner-controlled mode 0600",
        "error_codes": "ownership or permissions validation failures report permission (exit 5); malformed input reports invalid_input (exit 2)",
        "save": {"stdin":"same as gpa input","result":"saved|unchanged (idempotent, atomic, local-only)","file_mode":"0600","max_bytes":MAX_BASELINE_BYTES},
        "show": {"stdout":"the stored gpa_baseline document","requires_file_mode":"0600"}
    },
    "session": {
        "command": "buaa marks session [--online]",
        "description": "One explicit in-memory CAS login to GSMIS followed by the wdcjapp application document and bounded xscjcx.do reads of at most 3 pages and 512 source rows. Graduate accounts only. Credentials are stdin-only, and the command performs zero writes, persistence, refreshes or retries.",
        "input": {"type":"object","additionalProperties":false,"required":["authorized","username","password","intent","read"],"properties":{
            "authorized":{"const":true},
            "username":{"type":"string","writeOnly":true},
            "password":{"type":"string","writeOnly":true},
            "intent":{"type":"string","description":"exactly 'LOGIN <username> marks'"},
            "read":{"type":"object","additionalProperties":false,"required":["operation","enabled"],"properties":{
                "operation":{"const":"xscjcx"},
                "enabled":{"type":"boolean"},
                "xnxqdm":{"type":["string","null"],"pattern":SESSION_TERM_PATTERN,"description":"optional requested term; non-matching rows are counted, never projected"}}}}},
        "output": {"type":"object","required":["result"],"properties":{
            "result":{"enum":["disabled","parsed","business_error","degraded","fallback","sensitive_response_withheld","session_expired"]},
            "type":{"const":"marks_gsmis"},
            "records":{"type":"array","maxItems":MAX_SESSION_ROWS,"description":"datas.xscjcx.rows projected verbatim in page order, with the optional xnxqdm filter applied"},
            "requested_xnxqdm":session_term,
            "pages_requested":{"type":"integer","minimum":1,"maximum":3},
            "page_facts":{"type":"array","maxItems":3,"items":{"type":"object",
                "required":["page_number","requested_page_size","source_row_count","declared_total","declared_page_size","accepted"],
                "properties":{
                    "page_number":{"type":"integer","minimum":1,"maximum":3},
                    "requested_page_size":{"const":200},
                    "source_row_count":{"type":"integer","minimum":0},
                    "declared_total":{"type":["integer","null"],"minimum":0},
                    "declared_page_size":{"type":["integer","null"],"minimum":0},
                    "accepted":{"type":"boolean"}
                }}},
            "completeness":{"type":"object","required":["complete","reasons","max_pages","max_source_rows"],
                "properties":{
                    "complete":{"type":"boolean"},
                    "reasons":{"type":"array","items":{"type":"string"}},
                    "max_pages":{"const":3},
                    "max_source_rows":{"const":MAX_SESSION_ROWS}
                }}
        }}
    }})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

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

    // Single uniform band: every passing score carries 4.0, so a checked
    // arithmetic refusal cannot be confused with a banding change.
    const BAND_POLICY_INPUT: &str = r#"{"policy":{"kind":"table","id":"test-band",
        "source":"https://example.invalid/band","pass_min":60,
        "bands":[{"min":60,"max":100,"point":4.0}]}}"#;

    fn session_gpa_input() -> Value {
        json!({
            "policy": serde_json::from_str::<Value>(TABLE_POLICY).unwrap(),
            "marks_session": {
                "schema_version": 1,
                "type": "marks_gsmis",
                "result": "parsed",
                "requested_xnxqdm": "20261",
                "records": [
                    {"KCMC":"A","CJ":"92.00","XF":"4.5","XNXQDM":"20261"},
                    {"KCMC":"B","CJ":78,"XF":2,"XNXQDM":"20261"}
                ],
                "source_row_count": 3,
                "requested_term_match_count": 2,
                "other_term_count": 1,
                "unscoped_term_row_count": 0,
                "declared_total": 3,
                "completeness": {"complete": true, "reasons": []}
            }
        })
    }

    #[test]
    fn session_gpa_matches_explicit_courses_and_diff() {
        let mut input = session_gpa_input();
        let mut explicit = json!({
            "policy": input["policy"],
            "courses": [{"name":"A","score":92,"credit":4.5},{"name":"B","score":78,"credit":2}]
        });
        let mut baseline = gpa(&explicit.to_string());
        baseline["courses"][0]["score"] = json!(70);
        explicit["baseline"] = baseline.clone();
        input["baseline"] = baseline;

        let mut from_session = gpa(&input.to_string());
        assert_eq!(from_session["requested_xnxqdm"], "20261");
        from_session
            .as_object_mut()
            .unwrap()
            .remove("requested_xnxqdm");
        assert_eq!(from_session["diff"]["changed"][0]["name"], "A");
        assert_eq!(from_session, gpa(&explicit.to_string()));

        let session = &mut input["marks_session"];
        session["requested_xnxqdm"] = Value::Null;
        session["other_term_count"] = json!(0);
        session["source_row_count"] = json!(2);
        session["declared_total"] = json!(2);
        let unfiltered = gpa(&input.to_string());
        assert_eq!(unfiltered.get("requested_xnxqdm"), Some(&Value::Null));
        assert_eq!(unfiltered["gpa"], from_session["gpa"]);
    }

    #[test]
    fn session_gpa_baseline_preserves_requested_term() {
        let dir = std::env::temp_dir().join(format!("buaa-marks-session-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("baseline.json");
        let path = path.to_str().unwrap();
        let mut input = session_gpa_input();
        assert_eq!(baseline_save(&input.to_string(), path)["result"], "saved");
        assert_eq!(
            baseline_save(&input.to_string(), path)["result"],
            "unchanged"
        );
        let baseline = baseline_show(path);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(baseline["requested_xnxqdm"], "20261");
        input["baseline"] = baseline;
        assert_eq!(gpa(&input.to_string())["diff"]["gpa"]["delta"], 0.0);
        input["baseline"]["requested_xnxqdm"] = json!("20262");
        assert_eq!(gpa(&input.to_string())["error"], "invalid_input");
    }

    #[test]
    fn session_gpa_refuses_conflicting_or_incomplete_selection() {
        let mut input = session_gpa_input();
        input["courses"] = json!([]);
        assert_eq!(gpa(&input.to_string())["error"], "invalid_input");
        let without_selection = json!({"policy": input["policy"]});
        assert_eq!(gpa(&without_selection.to_string())["error"], "invalid_input");
        for (pointer, value) in [
            ("/completeness/complete", json!(false)),
            ("/declared_total", json!(4)),
            ("/other_term_count", json!(u64::MAX)),
            ("/unscoped_term_row_count", json!(1)),
            ("/records/0/XNXQDM", json!("20262")),
            ("/requested_xnxqdm", Value::Null),
        ] {
            let mut input = session_gpa_input();
            *input["marks_session"].pointer_mut(pointer).unwrap() = value;
            assert_eq!(
                gpa(&input.to_string())["error"],
                "invalid_input",
                "{pointer}"
            );
        }
    }

    #[test]
    fn session_gpa_refuses_unsupported_or_ambiguous_grades() {
        for grade in [
            Value::Null,
            json!("优秀"),
            json!("待录入"),
            json!("84.5"),
            json!(84.5),
            json!("84.0000000000000000000001"),
            json!(101),
        ] {
            let mut input = session_gpa_input();
            input["marks_session"]["records"][0]["CJ"] = grade;
            assert_eq!(gpa(&input.to_string())["error"], "invalid_input");
        }
        for field in ["KCMC", "CJ", "XF"] {
            let mut input = session_gpa_input();
            input["marks_session"]["records"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert_eq!(gpa(&input.to_string())["error"], "invalid_input", "{field}");
        }
        let mut input = session_gpa_input();
        input["marks_session"]["records"][0]["score"] = json!(80);
        assert_eq!(gpa(&input.to_string())["error"], "invalid_input");

        let repeated = session_gpa_input().to_string().replacen(
            r#""CJ":"92.00""#,
            r#""CJ":80,"CJ":"92.00""#,
            1,
        );
        assert_eq!(gpa(&repeated)["error"], "invalid_input");
    }

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
        assert_eq!(out["error"], "invalid_input");
        assert!(out.get("gpa").is_none());
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
        assert_eq!(out["error"], "invalid_input");
        assert!(out.get("gpa").is_none());
    }

    #[test]
    fn baseline_save_is_idempotent_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("buaa-marks-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("baseline.json");
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
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("baseline.json");
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
    fn baseline_save_reports_ownership_policy_failures_as_permission() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("buaa-marks-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let input = format!(r#"{{"policy":{} ,"courses":[]}}"#, TABLE_POLICY);
        let outside = root.join("outside.json");
        fs::write(&outside, "unchanged").unwrap();

        // Symlink-open failures retain their existing classification; explicit
        // ownership/permissions validation failures report permission.
        let file_link = root.join("baseline-link.json");
        symlink(&outside, &file_link).unwrap();
        assert_eq!(
            baseline_save(&input, file_link.to_str().unwrap())["error"],
            "invalid_input"
        );
        assert_eq!(fs::read_to_string(&outside).unwrap(), "unchanged");

        let parent_link = root.join("parent-link");
        symlink(&root, &parent_link).unwrap();
        let through_parent_link = parent_link.join("baseline.json");
        assert_eq!(
            baseline_save(&input, through_parent_link.to_str().unwrap())["error"],
            "invalid_input"
        );

        let shared = root.join("shared");
        fs::DirBuilder::new().mode(0o700).create(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            baseline_save(&input, shared.join("baseline.json").to_str().unwrap())["error"],
            "permission"
        );
        assert_eq!(
            baseline_show(shared.join("baseline.json").to_str().unwrap())["error"],
            "permission"
        );

        let nonfile = root.join("directory-target");
        fs::DirBuilder::new().mode(0o700).create(&nonfile).unwrap();
        assert_eq!(
            baseline_save(&input, nonfile.to_str().unwrap())["error"],
            "permission"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn baseline_save_keeps_malformed_values_as_invalid_input() {
        let root = std::env::temp_dir().join(format!("buaa-marks-format-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let input = format!(r#"{{"policy":{} ,"courses":[]}}"#, TABLE_POLICY);
        let path = root.join("baseline.json");

        // A relative path is a malformed value, not an ownership failure.
        assert_eq!(
            baseline_save(&input, "relative/path.json")["error"],
            "invalid_input"
        );
        // A path component beyond the filesystem name limit is malformed too.
        let long_component = root.join("x".repeat(300));
        assert_eq!(
            baseline_save(&input, long_component.to_str().unwrap())["error"],
            "invalid_input"
        );
        // A malformed stdin document stays an input error.
        assert_eq!(
            baseline_save("not json", path.to_str().unwrap())["error"],
            "invalid_input"
        );
        assert_eq!(
            baseline_save(
                r#"{"policy":{"kind":"table"},"courses":[]}"#,
                path.to_str().unwrap()
            )["error"],
            "invalid_input"
        );
        let _ = fs::remove_dir_all(&root);
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
    fn oversized_and_aggregate_credits_fail_closed() {
        for credit in ["2e304", "1e308"] {
            let input = format!(
                r#"{{"policy":{} ,"courses":[{{"name":"A","score":92,"credit":{credit}}}]}}"#,
                TABLE_POLICY
            );
            assert_eq!(gpa(&input)["error"], "invalid_input");
        }
        let per_course = serde_json::to_string(&(MAX_SAFE_CREDIT_TOTAL * 0.6)).unwrap();
        let aggregate = format!(
            r#"{{"policy":{} ,"courses":[{{"name":"A","score":92,"credit":{per_course}}},{{"name":"B","score":92,"credit":{per_course}}}]}}"#,
            TABLE_POLICY
        );
        assert_eq!(gpa(&aggregate)["error"], "invalid_input");
        let baseline = json!({
            "courses":[{"name":"A","score":92,"credit":2e304}]
        });
        assert!(parse_baseline_courses(&baseline).is_err());
    }

    #[test]
    fn largest_safe_credit_domain_keeps_numeric_outputs_finite() {
        let credit = serde_json::to_string(&(MAX_SAFE_CREDIT_TOTAL * 0.4)).unwrap();
        let input = format!(
            r#"{{"policy":{} ,"courses":[{{"name":"A","score":92,"credit":{credit}}}]}}"#,
            TABLE_POLICY
        );
        let output = gpa(&input);
        assert!(output.get("error").is_none());
        for field in ["counted_credits", "total_credits", "gpa"] {
            assert!(output[field].as_f64().unwrap().is_finite());
        }
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

    fn course(name: &str, score: u8, credit: f64) -> Course {
        Course {
            name: name.to_owned(),
            score,
            credit,
        }
    }

    #[test]
    fn conflicting_duplicate_course_identity_is_refused() {
        // Same name, different score.
        let conflict_score = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":2.0}},{{"name":"A","score":80,"credit":2.0}}]}}"#,
            TABLE_POLICY
        );
        let out = gpa(&conflict_score);
        assert_eq!(out["error"], "invalid_input");
        assert_eq!(
            out["message"],
            "conflicting duplicate course name in selection"
        );

        // Same name and score, different credit.
        let conflict_credit = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":2.0}},{{"name":"A","score":90,"credit":3.0}}]}}"#,
            TABLE_POLICY
        );
        assert_eq!(
            gpa(&conflict_credit)["message"],
            "conflicting duplicate course name in selection"
        );

        // An identical repeat is refused too: counting it twice would
        // double-weight the credits.
        let identical = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":2.0}},{{"name":"A","score":90,"credit":2.0}}]}}"#,
            TABLE_POLICY
        );
        let out = gpa(&identical);
        assert_eq!(out["error"], "invalid_input");
        assert_eq!(out["message"], "duplicate course name in selection");

        // The baseline side refuses conflicting identity before diffing.
        let baseline = r#"{
            "policy":{"kind":"table","id":"test-table","source":"https://example.invalid/policy",
                "pass_min":60,"bands":[{"min":85,"max":100,"point":4.0},{"min":75,"max":84,"point":3.0},{"min":60,"max":74,"point":2.0}]},
            "courses":[
                {"name":"A","score":90,"credit":2.0},
                {"name":"A","score":70,"credit":2.0}]
        }"#;
        let current = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":2.0}}],"baseline":{}}}"#,
            TABLE_POLICY, baseline
        );
        let out = gpa(&current);
        assert_eq!(out["error"], "invalid_input");
        assert!(out.get("gpa").is_none());

        // Distinct names stay admitted (control).
        let distinct = format!(
            r#"{{"policy":{},"courses":[{{"name":"A","score":90,"credit":2.0}},{{"name":"B","score":90,"credit":2.0}}]}}"#,
            TABLE_POLICY
        );
        assert_eq!(gpa(&distinct)["gpa"], 4.0);
    }

    #[test]
    fn checked_arithmetic_refuses_overflow_and_non_finite_values() {
        let raw: Value = serde_json::from_str(BAND_POLICY_INPUT).unwrap();
        let context = parse_policy(&raw).unwrap();

        // `compute` holds the finite domain on its own, so these refusals do
        // not depend on the parse-time credit bound.
        let overflow = [
            course("A", 90, f64::MAX / 4.0),
            course("B", 90, f64::MAX / 4.0),
        ];
        assert!(compute(&context, &overflow).is_err());
        for credit in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, 0.0, -1.0] {
            assert!(
                compute(&context, &[course("A", 90, credit)]).is_err(),
                "{credit}"
            );
        }
        assert!(compute(&context, &[course("A", 150, 1.0)]).is_err());

        // Finite, in-domain input still reproduces the same result exactly.
        let ok = [course("A", 92, 4.0), course("B", 78, 2.0)];
        let first = compute(&context, &ok).unwrap();
        let second = compute(&context, &ok).unwrap();
        assert_eq!(first.gpa, Some(4.0));
        assert_eq!(first.counted_credits, 6.0);
        assert_eq!(first.total_credits, 6.0);
        assert_eq!(first.lines, second.lines);
        assert_eq!(first.gpa, second.gpa);
        assert_eq!(first.counted_credits, second.counted_credits);
        assert_eq!(first.total_credits, second.total_credits);
    }

    #[test]
    fn unsupported_score_and_policy_kind_are_refused_not_guessed() {
        // A table that carries no point for a supplied score is refused
        // instead of being scored as a guessed 0.0.
        let raw: Value = serde_json::from_str(BAND_POLICY_INPUT).unwrap();
        let mut uncovered = parse_policy(&raw).unwrap();
        if let Policy::Table(bands, _) = &mut uncovered.policy {
            bands[0].min = 85;
        } else {
            panic!("test policy must be a table");
        }
        assert!(compute(&uncovered, &[course("A", 70, 2.0)]).is_err());

        // A NaN point can never reach a published number either.
        let mut not_a_number = parse_policy(&raw).unwrap();
        if let Policy::Table(bands, _) = &mut not_a_number.policy {
            bands[0].point = f64::NAN;
        } else {
            panic!("test policy must be a table");
        }
        assert!(compute(&not_a_number, &[course("A", 90, 2.0)]).is_err());

        // Published policy parsing refuses unknown kinds and non-finite or
        // out-of-range points.
        for policy in [
            r#"{"kind":"weighted","id":"x","source":"y"}"#,
            r#"{"kind":"table","id":"x","source":"y","bands":[{"min":60,"max":100,"point":1e400}]}"#,
            r#"{"kind":"table","id":"x","source":"y","bands":[{"min":60,"max":100,"point":6.0}]}"#,
        ] {
            let input = format!(r#"{{"policy":{policy},"courses":[]}}"#);
            assert_eq!(gpa(&input)["error"], "invalid_input", "{policy}");
        }
        let out = gpa(r#"{"policy":{"kind":"weighted","id":"x","source":"y"},"courses":[]}"#);
        assert_eq!(
            out["message"],
            "unsupported policy kind; expected table or formula"
        );
    }
}

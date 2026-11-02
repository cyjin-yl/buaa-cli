//! Strict offline GSMIS postgraduate timetable parsing and ICS conversion.
//!
//! The parser accepts operator-supplied term-list and timetable response bodies.
//! It never logs in, retries, or invents period times. ICS generation is delegated
//! to `timetable::check`, so floating local times, CRLF, folding and UIDs have one
//! implementation across undergraduate and postgraduate timetables.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Datelike, Duration, NaiveDate, Weekday};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const TERM_URL: &str =
    "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/modules/xskcb/kfdxnxqcx.do";
pub const TIMETABLE_URL: &str =
    "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/bykb/loadXskbData.do";

const MAX_WEEKS: usize = 104;
const MAX_PERIOD: u64 = 64;
const WEEKDAYS: [&str; 7] = [
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
];

#[derive(Debug)]
struct ParseError {
    reason: &'static str,
    message: String,
}

impl ParseError {
    fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

fn shape(path: &str, requirement: &str) -> ParseError {
    ParseError::new(
        "invalid_response_shape",
        format!("{path} must be {requirement}"),
    )
}

fn fallback(body: &str, output_type: &str, error: ParseError) -> Value {
    json!({
        "schema_version": 1,
        "type": output_type,
        "result": "fallback",
        "fallback_reason": error.reason,
        "message": error.message,
        "raw_response_base64": STANDARD.encode(body.as_bytes()),
        "raw_response_sha256": format!("{:x}", Sha256::digest(body.as_bytes())),
        "body_byte_length": body.len(),
        "content_type": Value::Null,
    })
}

fn invalid_input(message: &str) -> Value {
    json!({
        "schema_version": 1,
        "type": "timetable_pg",
        "error": "invalid_input",
        "message": message,
    })
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, ParseError> {
    value.as_object().ok_or_else(|| shape(path, "an object"))
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>, ParseError> {
    value.as_array().ok_or_else(|| shape(path, "an array"))
}

fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, ParseError> {
    object
        .get(key)
        .ok_or_else(|| shape(path, "present and non-null"))
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Map<String, Value>, ParseError> {
    self::object(required(object, key, path)?, path)
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Vec<Value>, ParseError> {
    self::array(required(object, key, path)?, path)
}

fn text(value: &Value, path: &str) -> Result<String, ParseError> {
    match value.as_str() {
        Some(value) if !value.trim().is_empty() => Ok(value.to_owned()),
        _ => Err(shape(path, "a non-blank string")),
    }
}

fn text_field(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<String, ParseError> {
    text(required(object, key, path)?, path)
}

fn optional_text(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, ParseError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(shape(path, "a string or null")),
    }
}

fn unsigned(value: &Value, path: &str) -> Result<u64, ParseError> {
    match value {
        Value::Number(value) => value
            .as_u64()
            .ok_or_else(|| shape(path, "a non-negative integer")),
        Value::String(value)
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value
                .parse()
                .map_err(|_| shape(path, "a non-negative integer"))
        }
        _ => Err(shape(path, "a non-negative integer or decimal string")),
    }
}

fn unsigned_field(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<u64, ParseError> {
    unsigned(required(object, key, path)?, path)
}

fn valid_term(term: &str) -> bool {
    let bytes = term.as_bytes();
    bytes.len() == 5
        && bytes[..4].iter().all(|byte| byte.is_ascii_digit())
        && matches!(bytes[4], b'1' | b'2' | b'3')
}

fn parse_date(value: &str) -> Option<NaiveDate> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..4].iter().all(|byte| byte.is_ascii_digit())
        || !bytes[5..7].iter().all(|byte| byte.is_ascii_digit())
        || !bytes[8..].iter().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let year = value[..4].parse().ok()?;
    let month = value[5..7].parse().ok()?;
    let day = value[8..].parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day)
}

fn period(value: u64, path: &str) -> Result<u32, ParseError> {
    if !(1..=MAX_PERIOD).contains(&value) {
        return Err(ParseError::new(
            "invalid_period",
            format!("{path} must be in 1..={MAX_PERIOD}"),
        ));
    }
    Ok(value as u32)
}

fn validate_bitmap(value: &str, path: &str) -> Result<(), ParseError> {
    if value.is_empty()
        || value.len() > MAX_WEEKS
        || !value.bytes().all(|byte| matches!(byte, b'0' | b'1'))
        || !value.bytes().any(|byte| byte == b'1')
    {
        return Err(ParseError::new(
            "invalid_week_bitmap",
            format!(
                "{path} must contain 1..={MAX_WEEKS} binary digits and at least one active week"
            ),
        ));
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct WeekRun {
    start: u32,
    end: u32,
    parity: &'static str,
}

/// Cover every set bit with runs accepted by the shared timetable engine.
/// Arbitrary bitmaps are split; they are never rounded to all/odd/even weeks.
fn week_runs(bitmap: &str) -> Vec<WeekRun> {
    let weeks: Vec<u32> = bitmap
        .bytes()
        .enumerate()
        .filter_map(|(index, bit)| (bit == b'1').then_some(index as u32 + 1))
        .collect();
    let mut runs = Vec::new();
    let mut index = 0;
    while index < weeks.len() {
        let start = weeks[index];
        let step = weeks
            .get(index + 1)
            .map(|next| next - start)
            .unwrap_or(0);
        if !matches!(step, 1 | 2) {
            runs.push(WeekRun {
                start,
                end: start,
                parity: "all",
            });
            index += 1;
            continue;
        }
        let mut end = weeks[index + 1];
        let mut next = index + 2;
        while next < weeks.len() && weeks[next] - weeks[next - 1] == step {
            end = weeks[next];
            next += 1;
        }
        runs.push(WeekRun {
            start,
            end,
            parity: if step == 2 {
                if start % 2 == 1 { "odd" } else { "even" }
            } else {
                "all"
            },
        });
        index = next;
    }
    runs
}

struct Term {
    code: String,
    name: String,
}

fn terms_inner(body: &str) -> Result<Vec<Term>, ParseError> {
    let response: Value = serde_json::from_str(body)
        .map_err(|_| ParseError::new("invalid_json", "response is not valid JSON"))?;
    let root = object(&response, "response")?;
    if unsigned_field(root, "code", "response.code")? != 0 {
        return Err(ParseError::new(
            "gsmis_error_code",
            "GSMIS term-list code is not 0",
        ));
    }
    let datas = object_field(root, "datas", "response.datas")?;
    let data = object_field(datas, "kfdxnxqcx", "response.datas.kfdxnxqcx")?;
    let rows = array_field(data, "rows", "response.datas.kfdxnxqcx.rows")?;
    let total = unsigned_field(
        data,
        "totalSize",
        "response.datas.kfdxnxqcx.totalSize",
    )?;
    if total != rows.len() as u64 {
        return Err(ParseError::new(
            "incomplete_term_list",
            "GSMIS totalSize does not equal the number of retained term rows",
        ));
    }
    let mut terms = Vec::with_capacity(rows.len());
    let mut seen = BTreeSet::new();
    for (index, row) in rows.iter().enumerate() {
        let path = format!("response.datas.kfdxnxqcx.rows[{index}]");
        let row = object(row, &path)?;
        let code = text_field(row, "XNXQDM", &format!("{path}.XNXQDM"))?;
        if !valid_term(&code) {
            return Err(ParseError::new(
                "invalid_term",
                format!("{path}.XNXQDM must contain four digits followed by 1, 2 or 3"),
            ));
        }
        if !seen.insert(code.clone()) {
            return Err(ParseError::new(
                "duplicate_term",
                format!("{path}.XNXQDM duplicates an earlier term"),
            ));
        }
        let name = text_field(
            row,
            "XNXQDM_DISPLAY",
            &format!("{path}.XNXQDM_DISPLAY"),
        )?;
        terms.push(Term { code, name });
    }
    terms.sort_by(|left, right| right.code.cmp(&left.code));
    Ok(terms)
}

/// Parse a GSMIS `kfdxnxqcx.do` response without network access.
pub fn parse_terms(body: &str) -> Value {
    match terms_inner(body) {
        Ok(terms) => {
            let terms: Vec<Value> = terms
                .into_iter()
                .enumerate()
                .map(|(index, term)| {
                    json!({"code": term.code, "name": term.name, "default": index == 0})
                })
                .collect();
            json!({
                "schema_version": 1,
                "type": "timetable_pg_terms",
                "result": "parsed",
                "terms": terms,
            })
        }
        Err(error) => fallback(body, "timetable_pg_terms", error),
    }
}

struct Course {
    first_class_date: Option<NaiveDate>,
}

struct Row {
    class_id: String,
    name: String,
    weekday: u32,
    first_period: u32,
    last_period: u32,
    bitmap: String,
    scheme: String,
    location: Option<String>,
}

// A source row's identity is independent of its bitmap, row order, displayed
// name and location. No stable upstream row ID is established, so a change to
// the class, weekday, period or scheme necessarily changes this derived ID.
fn row_identity(term: &str, row: &Row) -> String {
    let mut digest = Sha256::new();
    digest.update(b"buaa-cli/timetable-pg-row/v1\0");
    for value in [term, row.class_id.as_str(), row.scheme.as_str()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    for value in [row.weekday, row.first_period, row.last_period] {
        digest.update(value.to_be_bytes());
    }
    format!("{:x}", digest.finalize())
}

struct Slot {
    start: String,
    end: String,
    start_minutes: u32,
    end_minutes: u32,
}

fn clock(value: &Value, path: &str) -> Result<(u32, String), ParseError> {
    let hhmm = unsigned(value, path)?;
    let hour = (hhmm / 100) as u32;
    let minute = (hhmm % 100) as u32;
    if hhmm > 2359 || hour > 23 || minute > 59 {
        return Err(ParseError::new(
            "invalid_period_time",
            format!("{path} must be an HHMM time between 0000 and 2359"),
        ));
    }
    Ok((hour * 60 + minute, format!("{hour:02}:{minute:02}")))
}

fn parse_slots(root: &Map<String, Value>) -> Result<BTreeMap<(String, u32), Slot>, ParseError> {
    let plans = match root.get("jcfaList") {
        Some(value) => array(value, "response.jcfaList")?,
        None => {
            return Err(ParseError::new(
                "period_schedule_missing",
                "GSMIS response has no jcfaList period schedule",
            ));
        }
    };
    let mut slots = BTreeMap::new();
    for (plan_index, plan) in plans.iter().enumerate() {
        let plan_path = format!("response.jcfaList[{plan_index}]");
        let plan = object(plan, &plan_path)?;
        let list = match plan.get("skjcList") {
            Some(value) => array(value, &format!("{plan_path}.skjcList"))?,
            None => {
                return Err(ParseError::new(
                    "period_schedule_missing",
                    format!("{plan_path}.skjcList is missing"),
                ));
            }
        };
        for (slot_index, slot) in list.iter().enumerate() {
            let path = format!("{plan_path}.skjcList[{slot_index}]");
            let slot = object(slot, &path)?;
            let scheme = text_field(slot, "JCFADM", &format!("{path}.JCFADM"))?;
            let number = period(
                unsigned_field(slot, "DM", &format!("{path}.DM"))?,
                &format!("{path}.DM"),
            )?;
            let (start_minutes, start) = clock(
                required(slot, "KSSJ", &format!("{path}.KSSJ"))?,
                &format!("{path}.KSSJ"),
            )?;
            let (end_minutes, end) = clock(
                required(slot, "JSSJ", &format!("{path}.JSSJ"))?,
                &format!("{path}.JSSJ"),
            )?;
            if end_minutes <= start_minutes {
                return Err(ParseError::new(
                    "invalid_period_time",
                    format!("{path} must end after it starts on the same local day"),
                ));
            }
            let key = (scheme, number);
            if slots
                .insert(
                    key,
                    Slot {
                        start,
                        end,
                        start_minutes,
                        end_minutes,
                    },
                )
                .is_some()
            {
                return Err(ParseError::new(
                    "period_schedule_ambiguous",
                    format!("{path} duplicates a JCFADM/DM period entry"),
                ));
            }
        }
    }
    let mut previous: Option<(&str, &Slot)> = None;
    for ((scheme, _), slot) in &slots {
        if let Some((previous_scheme, previous_slot)) = previous {
            if previous_scheme == scheme
                && (slot.start_minutes < previous_slot.end_minutes
                    || slot.end_minutes <= previous_slot.end_minutes)
            {
                return Err(ParseError::new(
                    "invalid_period_time",
                    "period times within one JCFADM must increase without overlap",
                ));
            }
        }
        previous = Some((scheme.as_str(), slot));
    }
    Ok(slots)
}

fn first_offset(row: &Row) -> i64 {
    let first_week = row.bitmap.find('1').unwrap_or(0) as i64;
    first_week * 7 + i64::from(row.weekday - 1)
}

fn timetable_inner(body: &str, term: &str) -> Result<Value, ParseError> {
    if !valid_term(term) {
        return Err(ParseError::new(
            "invalid_term",
            "requested term must contain four digits followed by 1, 2 or 3",
        ));
    }
    let response: Value = serde_json::from_str(body)
        .map_err(|_| ParseError::new("invalid_json", "response is not valid JSON"))?;
    let root = object(&response, "response")?;
    if unsigned_field(root, "code", "response.code")? != 1 {
        return Err(ParseError::new(
            "gsmis_error_code",
            "GSMIS timetable code is not 1",
        ));
    }

    let course_values = array_field(root, "rwList", "response.rwList")?;
    let mut courses = BTreeMap::new();
    for (index, value) in course_values.iter().enumerate() {
        let path = format!("response.rwList[{index}]");
        let value = object(value, &path)?;
        let class_id = text_field(value, "BJDM", &format!("{path}.BJDM"))?;
        let actual_term = text_field(value, "XNXQDM", &format!("{path}.XNXQDM"))?;
        if actual_term != term {
            return Err(ParseError::new(
                "term_mismatch",
                format!("{path}.XNXQDM does not equal the requested term"),
            ));
        }
        let first_class_date = match optional_text(value, "SCSKRQ", &format!("{path}.SCSKRQ"))? {
            Some(date) if !date.trim().is_empty() => Some(parse_date(&date).ok_or_else(|| {
                ParseError::new(
                    "invalid_first_class_date",
                    format!("{path}.SCSKRQ must be a valid YYYY-MM-DD date"),
                )
            })?),
            _ => None,
        };
        if courses
            .insert(class_id, Course { first_class_date })
            .is_some()
        {
            return Err(ParseError::new(
                "invalid_response_shape",
                format!("{path}.BJDM duplicates an earlier course"),
            ));
        }
    }

    let row_values = array_field(root, "jgList", "response.jgList")?;
    let mut rows = Vec::with_capacity(row_values.len());
    for (index, value) in row_values.iter().enumerate() {
        let path = format!("response.jgList[{index}]");
        let value = object(value, &path)?;
        let class_id = text_field(value, "BJDM", &format!("{path}.BJDM"))?;
        if !courses.contains_key(&class_id) {
            return Err(ParseError::new(
                "course_reference_missing",
                format!("{path}.BJDM has no matching rwList course"),
            ));
        }
        text_field(value, "KCDM", &format!("{path}.KCDM"))?;
        let name = text_field(value, "KCMC", &format!("{path}.KCMC"))?;
        let weekday = unsigned_field(value, "XQ", &format!("{path}.XQ"))?;
        if !(1..=7).contains(&weekday) {
            return Err(ParseError::new(
                "invalid_weekday",
                format!("{path}.XQ must be in 1..=7"),
            ));
        }
        let first_period = period(
            unsigned_field(value, "KSJCDM", &format!("{path}.KSJCDM"))?,
            &format!("{path}.KSJCDM"),
        )?;
        let last_period = period(
            unsigned_field(value, "JSJCDM", &format!("{path}.JSJCDM"))?,
            &format!("{path}.JSJCDM"),
        )?;
        if last_period < first_period {
            return Err(ParseError::new(
                "invalid_period",
                format!("{path}.JSJCDM must not precede KSJCDM"),
            ));
        }
        let bitmap = text_field(value, "ZCBH", &format!("{path}.ZCBH"))?;
        validate_bitmap(&bitmap, &format!("{path}.ZCBH"))?;
        let scheme = text_field(value, "JCFADM", &format!("{path}.JCFADM"))?;
        let location = optional_text(value, "JASMC", &format!("{path}.JASMC"))?
            .filter(|location| !location.trim().is_empty());
        optional_text(value, "JGJSXM", &format!("{path}.JGJSXM"))?;
        rows.push(Row {
            class_id,
            name,
            weekday: weekday as u32,
            first_period,
            last_period,
            bitmap,
            scheme,
            location,
        });
    }

    // Validate every declared schedule, including schedules not used by a row.
    // No built-in BUAA or other-school period table is substituted here.
    let slots = parse_slots(root)?;

    if rows.is_empty() {
        return Ok(json!({
            "schema_version": 1,
            "type": "timetable_pg",
            "result": "parsed",
            "term": term,
            "course_count": courses.len(),
            "schedule_row_count": 0,
            "semester_start": Value::Null,
            "weeks": 0,
            "weeks_basis": "no_scheduled_rows",
            "normalized": {"semester": {"start_date": Value::Null, "weeks": 0}, "courses": []},
            "calendar": Value::Null,
            "calendar_status": "not_generated_without_a_derived_semester_start",
        }));
    }

    let mut starts = BTreeSet::new();
    for (class_id, course) in &courses {
        let offsets: Vec<i64> = rows
            .iter()
            .filter(|row| row.class_id == *class_id)
            .map(first_offset)
            .collect();
        let Some(offset) = offsets.into_iter().min() else {
            continue;
        };
        let first_date = course.first_class_date.ok_or_else(|| {
            ParseError::new(
                "first_class_date_missing",
                "every scheduled rwList course must provide SCSKRQ",
            )
        })?;
        let start = first_date
            .checked_sub_signed(Duration::days(offset))
            .ok_or_else(|| {
                ParseError::new(
                    "invalid_first_class_date",
                    "SCSKRQ and the week/weekday offset exceed the supported date range",
                )
            })?;
        starts.insert(start);
    }
    if starts.len() != 1 {
        let reason = if starts.is_empty() {
            "semester_start_unavailable"
        } else {
            "semester_start_conflict"
        };
        return Err(ParseError::new(
            reason,
            "SCSKRQ, ZCBH and XQ do not derive one consistent semester start",
        ));
    }
    let semester_start = *starts.iter().next().unwrap_or_else(|| unreachable!());
    if semester_start.weekday() != Weekday::Mon {
        return Err(ParseError::new(
            "semester_start_conflict",
            "derived semester start is not a Monday",
        ));
    }

    let weeks = rows
        .iter()
        .map(|row| row.bitmap.len())
        .max()
        .unwrap_or(0);
    let identities: Vec<String> = rows.iter().map(|row|row_identity(term,row)).collect();
    let mut engine_courses = Vec::new();
    let mut engine_source_ids = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let start_slot = slots
            .get(&(row.scheme.clone(), row.first_period))
            .ok_or_else(|| {
                ParseError::new(
                    "period_schedule_missing",
                    format!("response.jgList[{index}] has no matching KSJCDM period time"),
                )
            })?;
        let end_slot = slots
            .get(&(row.scheme.clone(), row.last_period))
            .ok_or_else(|| {
                ParseError::new(
                    "period_schedule_missing",
                    format!("response.jgList[{index}] has no matching JSJCDM period time"),
                )
            })?;
        if end_slot.end_minutes <= start_slot.start_minutes {
            return Err(ParseError::new(
                "invalid_period_time",
                format!("response.jgList[{index}] period range does not have positive duration"),
            ));
        }
        for number in row.first_period..=row.last_period {
            let included = slots.get(&(row.scheme.clone(), number)).ok_or_else(|| {
                ParseError::new(
                    "period_schedule_missing",
                    format!("response.jgList[{index}] has an unlisted included period"),
                )
            })?;
            if included.start_minutes < start_slot.start_minutes
                || included.end_minutes > end_slot.end_minutes
            {
                return Err(ParseError::new(
                    "invalid_period_time",
                    format!("response.jgList[{index}] interval truncates an included period"),
                ));
            }
        }
        for run in week_runs(&row.bitmap) {
            let mut course = json!({
                "name": row.name,
                "day": WEEKDAYS[row.weekday as usize - 1],
                "start_week": run.start,
                "end_week": run.end,
                "parity": run.parity,
                "start_time": start_slot.start,
                "end_time": end_slot.end,
            });
            if let Some(location) = &row.location {
                course["location"] = json!(location);
            }
            engine_courses.push(course);
            engine_source_ids.push(identities[index].as_str());
        }
    }

    let normalized = json!({
        "semester": {
            "start_date": semester_start.format("%Y-%m-%d").to_string(),
            "weeks": weeks,
        },
        "courses": engine_courses,
    });
    let engine_input = serde_json::to_string(&normalized).map_err(|_| {
        ParseError::new(
            "ics_conversion_rejected",
            "normalized timetable could not be serialized",
        )
    })?;
    let calendar = crate::timetable::check_with_source_identity(&engine_input, &engine_source_ids);
    if calendar.get("error").is_some() {
        return Err(ParseError::new(
            "ics_conversion_rejected",
            calendar
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("shared timetable engine rejected the normalized input"),
        ));
    }

    Ok(json!({
        "schema_version": 1,
        "type": "timetable_pg",
        "result": "parsed",
        "term": term,
        "course_count": courses.len(),
        "schedule_row_count": rows.len(),
        "semester_start": semester_start.format("%Y-%m-%d").to_string(),
        "weeks": weeks,
        "weeks_basis": "maximum_zcbh_length_not_an_official_semester_length",
        "normalized": normalized,
        "calendar": calendar,
    }))
}

/// Parse a GSMIS `loadXskbData.do` response and convert it through the shared
/// offline timetable ICS engine. `term` must be the explicitly selected XNXQDM.
pub fn parse_timetable(body: &str, term: &str) -> Value {
    match timetable_inner(body, term) {
        Ok(output) => output,
        Err(error) => fallback(body, "timetable_pg", error),
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
enum OfflineInput {
    #[serde(rename = "terms")]
    Terms {
        response: String,
        content_type: Option<String>,
    },
    #[serde(rename = "timetable")]
    Timetable {
        response: String,
        term: String,
        content_type: Option<String>,
    },
}

/// JSON-stdin adapter for integration with the command dispatcher.
pub fn check(input: &str) -> Value {
    let input: OfflineInput = match serde_json::from_str(input) {
        Ok(input) => input,
        Err(_) => {
            return invalid_input(
                "input must be a JSON object with operation and raw response; timetable also requires term",
            );
        }
    };
    let (mut output, content_type) = match input {
        OfflineInput::Terms { response, content_type } => {
            (parse_terms(&response), content_type)
        }
        OfflineInput::Timetable { response, term, content_type } => {
            if !valid_term(&term) {
                return invalid_input("timetable requires a valid term");
            }
            (parse_timetable(&response, &term), content_type)
        },
    };
    if output["result"] == "fallback" {
        output["content_type"] = json!(content_type);
    }
    output
}

/// Describe the offline command and the reviewed GSMIS protocol boundary.
pub fn schema() -> Value {
    json!({
        "command": "timetable-pg",
        "description": "Strict offline parsing of operator-supplied GSMIS term and timetable responses, with ICS generated by the existing timetable engine. No network access, login, retry, or default period-time table.",
        "protocol": {
            "term_url": TERM_URL,
            "term_method": "POST with no body; success code is 0; rows are datas.kfdxnxqcx.rows and totalSize must match",
            "timetable_url": TIMETABLE_URL,
            "timetable_method": "POST form ZC=&XNXQDM={term}&XH=&XQDM=; success code is 1",
            "online_implemented": false,
            "online_boundary": "A future online adapter must use a reviewed GSMIS source profile, the process-shared governor and an explicit GSMIS session reference. This module does not create a parallel HTTP or authentication path."
        },
        "input": {
            "type": "object",
            "additionalProperties": false,
            "required": ["operation", "response"],
            "oneOf": [
                {"properties": {"operation": {"const": "terms"}}, "not": {"required": ["term"]}},
                {"properties": {"operation": {"const": "timetable"}}, "required": ["term"]}
            ],
            "properties": {
                "operation": {"enum": ["terms", "timetable"]},
                "response": {"type": "string", "description": "Exact raw GSMIS response body as text, not a parsed JSON value."},
                "content_type": {"type": ["string", "null"], "description": "Original response Content-Type, retained unchanged in fallback; missing or null means unknown, never inferred from the endpoint."},
                "term": {"type": "string", "pattern": "^[0-9]{4}[123]$", "description": "Required for timetable; exact selected XNXQDM. Not accepted for terms."}
            }
        },
        "output": {
            "parsed_terms": "terms[] with code/name/default, sorted by descending term code",
            "parsed_timetable": "semester_start derived and cross-checked from SCSKRQ/ZCBH/XQ; weeks is only maximum bitmap length; normalized is the shared-engine input. Calendar UIDs bind the source term, class, weekday, periods and scheme rather than bitmap-run position; changing those identity fields changes the derived UID. Calendar is null for an explicitly empty jgList.",
            "fallback": {"required": ["result", "fallback_reason", "raw_response_base64", "raw_response_sha256", "body_byte_length", "content_type"], "description": "Any invalid JSON, error code, shape, reference, bitmap, date, period or missing-time failure retains the exact supplied bytes and original Content-Type (null when unknown) and never emits an empty or default-timed calendar. Raw responses may contain personal information."}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timetable_json() -> Value {
        json!({
            "code": 1,
            "rwList": [{
                "BJDM": "class-1",
                "XNXQDM": "20261",
                "SCSKRQ": "2026-09-08"
            }],
            "jgList": [{
                "BJDM": "class-1",
                "KCDM": "course-1",
                "KCMC": "Synthetic postgraduate course",
                "XQ": 2,
                "KSJCDM": 1,
                "JSJCDM": 2,
                "ZCBH": "1100",
                "JCFADM": "01",
                "JASMC": "Synthetic room",
                "JGJSXM": "Synthetic teacher"
            }],
            "jcfaList": [{
                "JCFADM": "01",
                "skjcList": [
                    {"JCFADM": "01", "DM": "1", "KSSJ": 800, "JSSJ": 845},
                    {"JCFADM": "01", "DM": "2", "KSSJ": 850, "JSSJ": 935},
                    {"JCFADM": "01", "DM": "3", "KSSJ": 950, "JSSJ": 1035}
                ]
            }]
        })
    }

    #[test]
    fn parses_terms_and_rejects_incomplete_lists() {
        let body = json!({
            "code": "0",
            "datas": {"kfdxnxqcx": {"totalSize": 2, "rows": [
                {"XNXQDM": "20253", "XNXQDM_DISPLAY": "older"},
                {"XNXQDM": "20261", "XNXQDM_DISPLAY": "newer"}
            ]}}
        })
        .to_string();
        let output = parse_terms(&body);
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["terms"][0]["code"], "20261");
        assert_eq!(output["terms"][0]["default"], true);
        assert_eq!(output["terms"][1]["default"], false);

        let incomplete = body.replace("\"totalSize\":2", "\"totalSize\":3");
        let output = parse_terms(&incomplete);
        assert_eq!(output["fallback_reason"], "incomplete_term_list");
        assert!(output["raw_response_base64"].as_str().is_some());
    }

    #[test]
    fn normal_rows_derive_dates_and_use_shared_ics_engine() {
        let output = parse_timetable(&timetable_json().to_string(), "20261");
        assert_eq!(output["result"], "parsed", "{output}");
        assert_eq!(output["semester_start"], "2026-09-07");
        assert_eq!(output["weeks"], 4);
        assert_eq!(output["calendar"]["type"], "timetable_ics");
        assert_eq!(output["calendar"]["event_count"], 2);
        let ics = output["calendar"]["ics"].as_str().unwrap();
        assert!(ics.contains("DTSTART:20260908T080000"));
        assert!(ics.contains("DTSTART:20260915T080000"));
        assert!(ics.contains("DTEND:20260908T093500"));
        assert!(ics.contains("LOCATION:Synthetic room"));
        assert!(!ics.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn source_occurrence_identity_survives_bitmap_changes_and_row_reordering() {
        fn uid(output: &Value, summary: &str, date: &str) -> String {
            let unfolded = output["calendar"]["ics"].as_str().unwrap().replace("\r\n ", "");
            for event in unfolded.split("BEGIN:VEVENT\r\n").skip(1) {
                if event.lines().any(|line|line.trim_end() == format!("SUMMARY:{summary}"))
                    && event.lines().any(|line|line.starts_with(&format!("DTSTART:{date}")))
                {
                    return event.lines().find_map(|line|line.trim_end().strip_prefix("UID:"))
                        .unwrap().to_owned();
                }
            }
            panic!("expected synthetic event missing");
        }

        let mut source = timetable_json();
        source["jgList"][0]["KCMC"] = json!("Course A");
        source["jgList"][0]["ZCBH"] = json!("1001");
        let mut second = source["jgList"][0].clone();
        second["BJDM"] = json!("class-2");
        second["KCDM"] = json!("course-2");
        second["KCMC"] = json!("Course B");
        second["ZCBH"] = json!("0001");
        source["jgList"].as_array_mut().unwrap().push(second);
        source["rwList"].as_array_mut().unwrap().push(json!({
            "BJDM":"class-2","XNXQDM":"20261","SCSKRQ":"2026-09-29"
        }));

        let before = parse_timetable(&source.to_string(), "20261");
        assert_eq!(before["result"], "parsed", "{before}");
        let a = uid(&before,"Course A","20260929");
        let b = uid(&before,"Course B","20260929");
        assert_ne!(a,b);

        source["jgList"][0]["ZCBH"] = json!("1111");
        let changed = parse_timetable(&source.to_string(), "20261");
        assert_eq!(changed["result"], "parsed", "{changed}");
        assert_eq!(uid(&changed,"Course A","20260929"),a);
        assert_eq!(uid(&changed,"Course B","20260929"),b);

        source["jgList"].as_array_mut().unwrap().reverse();
        let reordered = parse_timetable(&source.to_string(), "20261");
        assert_eq!(uid(&reordered,"Course A","20260929"),a);
        assert_eq!(uid(&reordered,"Course B","20260929"),b);

        let duplicate = source["jgList"][0].clone();
        source["jgList"].as_array_mut().unwrap().push(duplicate);
        let rejected = parse_timetable(&source.to_string(), "20261");
        assert_eq!(rejected["result"],"fallback");
        assert_eq!(rejected["fallback_reason"],"ics_conversion_rejected");
    }

    #[test]
    fn arbitrary_odd_even_and_sparse_bitmaps_are_not_rounded() {
        assert_eq!(
            week_runs("1010"),
            vec![WeekRun {
                start: 1,
                end: 3,
                parity: "odd"
            }]
        );
        assert_eq!(
            week_runs("0101"),
            vec![WeekRun {
                start: 2,
                end: 4,
                parity: "even"
            }]
        );
        assert_eq!(
            week_runs("1001"),
            vec![
                WeekRun {
                    start: 1,
                    end: 1,
                    parity: "all"
                },
                WeekRun {
                    start: 4,
                    end: 4,
                    parity: "all"
                }
            ]
        );

        let mut body = timetable_json();
        body["jgList"][0]["ZCBH"] = json!("0101");
        body["rwList"][0]["SCSKRQ"] = json!("2026-09-15");
        let output = parse_timetable(&body.to_string(), "20261");
        assert_eq!(output["calendar"]["event_count"], 2, "{output}");
        let ics = output["calendar"]["ics"].as_str().unwrap();
        assert!(ics.contains("DTSTART:20260915T080000"));
        assert!(ics.contains("DTSTART:20260929T080000"));
        assert!(!ics.contains("DTSTART:20260908T080000"));
    }

    #[test]
    fn missing_period_schedule_is_fallback_not_default_times() {
        let mut body = timetable_json();
        body["jcfaList"] = json!([]);
        let raw = body.to_string();
        let output = parse_timetable(&raw, "20261");
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["fallback_reason"], "period_schedule_missing");
        assert!(output.get("calendar").is_none());
        assert!(output.get("event_count").is_none());
        assert_eq!(
            STANDARD
                .decode(output["raw_response_base64"].as_str().unwrap())
                .unwrap(),
            raw.as_bytes()
        );
    }

    #[test]
    fn error_codes_and_non_json_retain_raw_evidence() {
        for (body, term, expected_type) in [
            (json!({"code": 1, "datas": {"kfdxnxqcx": {"totalSize": 0, "rows": []}}}).to_string(), None, "timetable_pg_terms"),
            (json!({"code": 0, "rwList": [], "jgList": [], "jcfaList": []}).to_string(), Some("20261"), "timetable_pg"),
        ] {
            let output = match term {
                Some(term) => parse_timetable(&body, term),
                None => parse_terms(&body),
            };
            assert_eq!(output["type"], expected_type);
            assert_eq!(output["fallback_reason"], "gsmis_error_code");
            assert_eq!(output["body_byte_length"], body.len());
        }
        let output = parse_timetable("<html>not json</html>", "20261");
        assert_eq!(output["fallback_reason"], "invalid_json");
        assert!(output.get("calendar").is_none());
    }

    #[test]
    fn boundaries_and_calendar_conflicts_fail_closed() {
        for (field, value) in [
            ("XQ", json!(0)),
            ("XQ", json!(8)),
            ("KSJCDM", json!(3)),
            ("ZCBH", json!("")),
            ("ZCBH", json!("0102")),
            ("ZCBH", json!("0000")),
        ] {
            let mut body = timetable_json();
            body["jgList"][0][field] = value;
            let output = parse_timetable(&body.to_string(), "20261");
            assert_eq!(output["result"], "fallback", "{field}");
            assert!(output.get("calendar").is_none());
        }

        let mut bad_date = timetable_json();
        bad_date["rwList"][0]["SCSKRQ"] = json!("2026-02-30");
        assert_eq!(
            parse_timetable(&bad_date.to_string(), "20261")["fallback_reason"],
            "invalid_first_class_date"
        );

        let mut conflict = timetable_json();
        conflict["rwList"][0]["SCSKRQ"] = json!("2026-09-09");
        assert_eq!(
            parse_timetable(&conflict.to_string(), "20261")["fallback_reason"],
            "semester_start_conflict"
        );
    }

    #[test]
    fn reversed_or_overlapping_periods_preserve_fallback_evidence() {
        for (start, end) in [(800, 1000), (1000, 1045)] {
            let mut body = timetable_json();
            body["jcfaList"][0]["skjcList"][0]["KSSJ"] = json!(start);
            body["jcfaList"][0]["skjcList"][0]["JSSJ"] = json!(end);
            let raw = body.to_string();
            let output = parse_timetable(&raw, "20261");
            assert_eq!(output["fallback_reason"], "invalid_period_time");
            assert!(output.get("calendar").is_none());
            assert_eq!(STANDARD.decode(output["raw_response_base64"].as_str().unwrap()).unwrap(), raw.as_bytes());
        }
    }

    #[test]
    fn fallback_preserves_content_type_bytes_and_digest() {
        let raw = "<html>synthetic login page</html>\r\n";
        let mime = "text/html; charset=UTF-8";
        let output = check(&json!({"operation":"timetable", "term":"20261", "response":raw, "content_type":mime}).to_string());
        assert_eq!(output["content_type"], mime);
        assert_eq!(output["fallback_reason"], "invalid_json");
        let decoded = STANDARD.decode(output["raw_response_base64"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, raw.as_bytes());
        assert_eq!(output["body_byte_length"], decoded.len());
        assert_eq!(output["raw_response_sha256"], format!("{:x}", Sha256::digest(&decoded)));
        assert_eq!(parse_terms(raw)["content_type"], Value::Null);
    }

    #[test]
    fn schema_branches_match_term_presence_and_null_rules() {
        let contract = schema();
        assert_eq!(contract["input"]["oneOf"][0]["not"]["required"], json!(["term"]));
        assert_eq!(contract["input"]["oneOf"][1]["required"], json!(["term"]));
        assert_eq!(contract["input"]["properties"]["term"]["type"], "string");
        let terms = json!({"code":0,"datas":{"kfdxnxqcx":{"totalSize":0,"rows":[]}}}).to_string();
        assert_eq!(check(&json!({"operation":"terms","response":terms}).to_string())["result"], "parsed");
        for term in [Value::Null, json!("20261")] {
            assert_eq!(check(&json!({"operation":"terms","response":terms,"term":term}).to_string())["error"], "invalid_input");
        }
        for request in [
            json!({"operation":"timetable","response":"{}"}),
            json!({"operation":"timetable","response":"{}","term":null}),
        ] {
            assert_eq!(check(&request.to_string())["error"], "invalid_input");
        }
        for content_type in [None, Some(Value::Null), Some(json!("application/problem+json"))] {
            let mut request = json!({"operation":"terms","response":"not json"});
            if let Some(value) = content_type {
                request["content_type"] = value;
            }
            assert_eq!(check(&request.to_string())["result"], "fallback");
        }
    }

    #[test]
    fn term_and_course_references_are_not_inferred() {
        let mut body = timetable_json();
        body["rwList"][0]["XNXQDM"] = json!("20253");
        assert_eq!(parse_timetable(&body.to_string(), "20261")["fallback_reason"], "term_mismatch");
        body = timetable_json();
        body["jgList"][0]["BJDM"] = json!("unlisted-class");
        assert_eq!(parse_timetable(&body.to_string(), "20261")["fallback_reason"], "course_reference_missing");
    }

    #[test]
    fn bitmap_and_period_limits_and_missing_interior_are_rejected() {
        for (field, value) in [
            ("ZCBH", json!("1".repeat(MAX_WEEKS + 1))),
            ("KSJCDM", json!(0)),
            ("JSJCDM", json!(MAX_PERIOD + 1)),
            ("XQ", json!(1.5)),
        ] {
            let mut body = timetable_json();
            body["jgList"][0][field] = value;
            assert_eq!(parse_timetable(&body.to_string(), "20261")["result"], "fallback");
        }
        let mut body = timetable_json();
        body["jgList"][0]["JSJCDM"] = json!(3);
        body["jcfaList"][0]["skjcList"].as_array_mut().unwrap().remove(1);
        assert_eq!(parse_timetable(&body.to_string(), "20261")["fallback_reason"], "period_schedule_missing");
    }

    #[test]
    fn empty_scheduled_rows_are_explicit_not_parse_failure() {
        let mut body = timetable_json();
        body["jgList"] = json!([]);
        let output = parse_timetable(&body.to_string(), "20261");
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["schedule_row_count"], 0);
        assert_eq!(output["calendar"], Value::Null);
        assert_eq!(output["weeks_basis"], "no_scheduled_rows");
    }

    #[test]
    fn long_names_keep_shared_folding_and_json_adapter_dispatches() {
        let mut body = timetable_json();
        body["jgList"][0]["KCMC"] = json!("x".repeat(160));
        let input = json!({
            "operation": "timetable",
            "term": "20261",
            "response": body.to_string(),
        })
        .to_string();
        let output = check(&input);
        assert_eq!(output["result"], "parsed", "{output}");
        let ics = output["calendar"]["ics"].as_str().unwrap();
        assert!(ics.split("\r\n").all(|line| line.len() <= 75));
        assert!(ics.contains("\r\n SUMMARY:") || ics.contains("\r\n x"));
    }
}

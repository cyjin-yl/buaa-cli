//! Offline timetable-to-ICS conversion.
//!
//! Maps a semester schedule to absolute local datetimes and emits a
//! standards-compliant RFC 5545 iCalendar document. The command is offline:
//! it performs no network access and no writes. It never contacts a campus
//! service and never mutates anything; it only transforms the supplied
//! schedule into ICS text.
//!
//! The mapping contract:
//! - `semester.start_date` is the date of week 1, day Monday (the first
//!   calendar day of the semester).
//! - A course occurrence in week `w` on weekday `d` (Monday = 0 .. Sunday = 6)
//!   falls on `start_date + (w - 1) * 7 + d` days.
//! - `parity` filters weeks: `all` keeps every week, `odd` keeps odd week
//!   numbers, `even` keeps even week numbers.
//! - Occurrences whose date falls past the last day of the semester
//!   (`start_date + weeks * 7 - 1`) are dropped.
//!
//! The ICS uses floating local date-times (the times exactly as supplied, with
//! no timezone offset applied), which RFC 5545 permits. Lines are folded to at
//! most 75 octets (excluding CRLF) and the document uses CRLF line endings.
//!
//! A separate `session` entry point performs, on explicit authorization and
//! `--online`, one in-memory CAS sign-on to the graduate timetable service
//! followed by exactly one `loadXskbData.do` read in the same invocation. It
//! never retries, refreshes, caches or adopts upstream cookies, and credential
//! material never leaves the invocation.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use zeroize::Zeroizing;

use crate::{
    governor::{Governor, Outcome, RequestKind, RequestLease},
    net::{self, Error},
    recordings::session::{self as cas, CasService, SsoCredentials},
};

const MAX_COURSES: usize = 512;
const MAX_WEEKS: u32 = 104;

/// Days from 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let mut y = year;
    let m = month as i64;
    if m <= 2 {
        y -= 1;
    }
    let era = floor_div(y, 400);
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + (day as i64) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

fn floor_div(a: i64, b: i64) -> i64 {
    let q = a / b;
    let r = a % b;
    if (r != 0) && ((r < 0) != (b < 0)) {
        q - 1
    } else {
        q
    }
}

/// Civil date (year, month, day) for days-from-1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = floor_div(z, 146097);
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if m <= 2 {
        y += 1;
    }
    (y, m as u32, d)
}

/// Weekday with Monday = 0 .. Sunday = 6.
#[cfg(test)]
fn weekday_monday_index(z: i64) -> u32 {
    (((z + 3) % 7) + 7) as u32 % 7
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Parse a `YYYY-MM-DD` date; returns days-from-1970-01-01.
fn parse_date(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[0..4].iter().all(|b| b.is_ascii_digit())
        || !bytes[5..7].iter().all(|b| b.is_ascii_digit())
        || !bytes[8..10].iter().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let year: i64 = value[0..4].parse().ok()?;
    let month: u32 = value[5..7].parse().ok()?;
    let day: u32 = value[8..10].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// Format days-from-1970-01-01 as an ICS date-time `YYYYMMDDTHHMMSS`.
fn ics_datetime(z: i64, hour: u32, minute: u32) -> String {
    let (y, m, d) = civil_from_days(z);
    format!("{:04}{:02}{:02}T{:02}{:02}00", y, m, d, hour, minute)
}

/// Parse an `HH:MM` time of day into (hour, minute).
fn parse_time(value: &str) -> Option<(u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || !bytes[0..2].iter().all(|b| b.is_ascii_digit())
        || !bytes[3..5].iter().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let hour: u32 = value[0..2].parse().ok()?;
    let minute: u32 = value[3..5].parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some((hour, minute))
}

fn weekday_offset(value: &str) -> Option<u32> {
    let v = value.to_ascii_lowercase();
    let full = [
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
    ];
    let abbr = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    for (i, name) in full.iter().enumerate() {
        if v == *name || v == abbr[i] {
            return Some(i as u32);
        }
    }
    None
}

/// Escape a text value for an RFC 5545 property value.
fn escape_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
}

/// Largest UTF-8 character boundary at or before `target`.
fn char_boundary(bytes: &[u8], target: usize) -> usize {
    let mut i = target.min(bytes.len());
    while i > 0 && i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i
}

/// Fold a logical line into physical lines of at most 75 octets each
/// (excluding CRLF); continuation lines are prefixed with a single space.
fn fold_line(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    if bytes.len() <= 75 {
        return vec![line.to_string()];
    }
    let mut out = Vec::new();
    let mut pos = 0;
    let mut first = true;
    while pos < bytes.len() {
        let budget = if first { 75 } else { 74 };
        let cut = char_boundary(bytes, pos + budget);
        if cut <= pos {
            break;
        }
        let segment = line.get(pos..cut).unwrap();
        out.push(if first {
            segment.to_string()
        } else {
            format!(" {}", segment)
        });
        pos = cut;
        first = false;
    }
    out
}

struct Occurrence {
    date_z: i64,
    start: (u32, u32),
    end: (u32, u32),
}

struct Course {
    name: String,
    location: Option<String>,
    day: u32,
    start_week: u32,
    end_week: u32,
    parity: u8, // 0 all, 1 odd, 2 even
    start: (u32, u32),
    end: (u32, u32),
}

fn parse_parity(value: &str) -> Option<u8> {
    match value.to_ascii_lowercase().as_str() {
        "all" => Some(0),
        "odd" => Some(1),
        "even" => Some(2),
        _ => None,
    }
}

fn parse_course(index: usize, value: &Value) -> Result<Course, String> {
    let get = |field: &str| -> Result<&Value, String> {
        value
            .get(field)
            .ok_or_else(|| format!("course {index}: missing {field}"))
    };
    let name = get("name")?
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("course {index}: name must be a non-empty string"))?
        .to_string();
    let day = weekday_offset(
        get("day")?
            .as_str()
            .ok_or_else(|| format!("course {index}: day must be a weekday string"))?,
    )
    .ok_or_else(|| format!("course {index}: invalid day"))?;
    let start_week = get("start_week")?
        .as_u64()
        .filter(|s| *s >= 1)
        .ok_or_else(|| format!("course {index}: start_week must be >= 1"))?
        as u32;
    let end_week = get("end_week")?
        .as_u64()
        .ok_or_else(|| format!("course {index}: end_week must be an integer"))?
        as u32;
    if start_week > end_week {
        return Err(format!(
            "course {index}: start_week {start_week} must be <= end_week {end_week}",
        ));
    }
    let parity = match value.get("parity") {
        None | Some(Value::Null) => 0,
        Some(Value::String(s)) => {
            parse_parity(s).ok_or_else(|| format!("course {index}: invalid parity"))?
        }
        _ => return Err(format!("course {index}: parity must be a string")),
    };
    let (sh, sm) = parse_time(
        get("start_time")?
            .as_str()
            .ok_or_else(|| format!("course {index}: start_time must be HH:MM"))?,
    )
    .ok_or_else(|| format!("course {index}: invalid start_time"))?;
    let (eh, em) = parse_time(
        get("end_time")?
            .as_str()
            .ok_or_else(|| format!("course {index}: end_time must be HH:MM"))?,
    )
    .ok_or_else(|| format!("course {index}: invalid end_time"))?;
    if (eh, em) <= (sh, sm) {
        return Err(format!("course {index}: end_time must be after start_time"));
    }
    let location = match value.get("location") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(_) => return Err(format!("course {index}: location must be a string")),
    };
    Ok(Course {
        name,
        location,
        day,
        start_week,
        end_week,
        parity,
        start: (sh, sm),
        end: (eh, em),
    })
}

fn occurrences(semester_start: i64, weeks: u32, course: &Course) -> Vec<Occurrence> {
    let last_day = semester_start + (weeks as i64) * 7 - 1;
    let mut out = Vec::new();
    for week in course.start_week..=course.end_week {
        match course.parity {
            1 if week % 2 == 0 => continue,
            2 if week % 2 == 1 => continue,
            _ => {}
        }
        let z = semester_start + ((week - 1) as i64) * 7 + (course.day as i64);
        if z > last_day {
            continue;
        }
        out.push(Occurrence {
            date_z: z,
            start: course.start,
            end: course.end,
        });
    }
    out
}

/// Compare a timetable schedule against the ICS mapping contract and emit a
/// standards-compliant RFC 5545 document. Offline: no network, no writes.
pub fn check(input: &str) -> Value {
    check_inner(input, None)
}

/// Internal source-bound identity for adapters that split one source schedule
/// row into several engine courses. The public generic timetable retains its
/// existing positional identity contract.
pub(crate) fn check_with_source_identity(input: &str, source_ids: &[&str]) -> Value {
    check_inner(input, Some(source_ids))
}

fn check_inner(input: &str, source_ids: Option<&[&str]>) -> Value {
    let parsed: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => {
            return json!({
                "schema_version": 1,
                "type": "timetable_ics",
                "error": "invalid_input",
                "message": "input must be a JSON object with semester and courses"
            });
        }
    };
    let invalid = |message: String| -> Value {
        json!({
            "schema_version": 1,
            "type": "timetable_ics",
            "error": "invalid_input",
            "message": message
        })
    };

    let semester = match parsed.get("semester") {
        Some(v) if v.is_object() => v,
        _ => return invalid("semester must be an object".into()),
    };
    let start_date = match semester
        .get("start_date")
        .and_then(Value::as_str)
        .and_then(parse_date)
    {
        Some(z) => z,
        None => return invalid("semester.start_date must be a valid YYYY-MM-DD date".into()),
    };
    let weeks = match semester
        .get("weeks")
        .and_then(Value::as_u64)
        .filter(|w| *w >= 1 && *w <= MAX_WEEKS as u64)
    {
        Some(w) => w as u32,
        None => {
            return invalid(format!(
                "semester.weeks must be an integer in 1..={MAX_WEEKS}"
            ));
        }
    };
    let courses_value = match parsed.get("courses").and_then(Value::as_array) {
        Some(v) => v,
        _ => return invalid("courses must be an array".into()),
    };
    if courses_value.len() > MAX_COURSES {
        return invalid(format!("at most {MAX_COURSES} courses are supported"));
    }

    let mut courses: Vec<Course> = Vec::new();
    for (i, c) in courses_value.iter().enumerate() {
        match parse_course(i + 1, c) {
            Ok(course) => courses.push(course),
            Err(message) => return invalid(message),
        }
    }
    if source_ids.is_some_and(|ids| {
        ids.len() != courses.len()
            || ids.iter().any(|id| {
                id.len() != 64
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    }) {
        return invalid("invalid or mismatched source identities".into());
    }

    // Build the ICS document.
    let stamp = format!("{}T000000Z", {
        let (y, m, d) = civil_from_days(start_date);
        format!("{:04}{:02}{:02}", y, m, d)
    });
    let (sy, sm, sd) = civil_from_days(start_date);
    let semester_start_iso = format!("{:04}-{:02}-{:02}", sy, sm, sd);

    let mut logical: Vec<String> = vec![
        "BEGIN:VCALENDAR".into(),
        "VERSION:2.0".into(),
        "PRODID:-//buaa-cli//timetable ics 1.0//EN".into(),
        "CALSCALE:GREGORIAN".into(),
    ];

    let mut event_count = 0usize;
    let mut seen_source_occurrences = std::collections::HashSet::new();
    for (ci, course) in courses.iter().enumerate() {
        for occ in occurrences(start_date, weeks, course) {
            let uid = if let Some(ids) = source_ids {
                let id = ids[ci];
                if !seen_source_occurrences.insert((id, occ.date_z)) {
                    return invalid("ambiguous duplicate source occurrence".into());
                }
                format!(
                    "buaa-cli/timetable-pg/{semester_start_iso}/{id}/{}",
                    occ.date_z
                )
            } else {
                format!(
                    "buaa-cli/timetable/{semester_start_iso}/{ci}/{}",
                    occ.date_z
                )
            };
            logical.push("BEGIN:VEVENT".into());
            logical.push(format!("UID:{uid}"));
            logical.push(format!("DTSTAMP:{stamp}"));
            logical.push(format!(
                "DTSTART:{}",
                ics_datetime(occ.date_z, occ.start.0, occ.start.1)
            ));
            logical.push(format!(
                "DTEND:{}",
                ics_datetime(occ.date_z, occ.end.0, occ.end.1)
            ));
            logical.push(format!("SUMMARY:{}", escape_text(&course.name)));
            if let Some(location) = &course.location {
                logical.push(format!("LOCATION:{}", escape_text(location)));
            }
            logical.push("END:VEVENT".into());
            event_count += 1;
        }
    }
    logical.push("END:VCALENDAR".into());

    let ics: String = logical
        .iter()
        .flat_map(|s| fold_line(s))
        .collect::<Vec<_>>()
        .join("\r\n");

    json!({
        "schema_version": 1,
        "type": "timetable_ics",
        "semester_start": semester_start_iso,
        "weeks": weeks,
        "event_count": event_count,
        "ics": ics
    })
}

// ---------------------------------------------------------------------------
// Graduate timetable session: one explicit in-memory CAS login to GSMIS
// followed by exactly one loadXskbData.do read. Secrets are stdin-only inputs;
// they are never persisted, logged or placed inside a generic Value tree. The
// read performs no writes, retries, refreshes, pagination or cookie adoption.

const SESSION_BODY_LIMIT: u64 = 8 * 1024 * 1024;
const SESSION_MAX_INPUT: usize = 65536;
const TIMETABLE_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/bykb/loadXskbData.do";
const TIMETABLE_REFERER: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do";

fn error(code: &'static str, message: &'static str) -> Error {
    Error::new(code, message)
}

fn session_invalid() -> Error {
    error(
        "invalid_input",
        "timetable session input does not match the xskb contract",
    )
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

// Serde's struct derives also accept positional sequences. This boundary
// admits JSON objects only, without a credential-bearing Value tree.
fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
}

struct SessionInput {
    authorized: bool,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    intent: Zeroizing<String>,
    read: SessionRead,
}

impl<'de> Deserialize<'de> for SessionInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            authorized: bool,
            #[serde(deserialize_with = "deserialize_secret")]
            username: Zeroizing<String>,
            #[serde(deserialize_with = "deserialize_secret")]
            password: Zeroizing<String>,
            #[serde(deserialize_with = "deserialize_secret")]
            intent: Zeroizing<String>,
            #[serde(deserialize_with = "deserialize_object")]
            read: SessionRead,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            authorized: raw.authorized,
            username: raw.username,
            password: raw.password,
            intent: raw.intent,
            read: raw.read,
        })
    }
}

struct SessionRead {
    enabled: bool,
    xnxqdm: String,
}

impl<'de> Deserialize<'de> for SessionRead {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum Raw {
            Xskb { enabled: bool, xnxqdm: String },
        }
        let (enabled, xnxqdm) = match deserialize_object(deserializer)? {
            Raw::Xskb { enabled, xnxqdm } => (enabled, xnxqdm),
        };
        Ok(Self { enabled, xnxqdm })
    }
}

/// The requested term filter is the exact five-digit XNXQDM code, matching the
/// shared yjsxk session contract.
fn valid_term_code(term: &str) -> bool {
    let bytes = term.as_bytes();
    bytes.len() == 5 && bytes.iter().all(u8::is_ascii_digit)
}

fn xskb_request(client: &Client, cookie: &str, term: &str) -> reqwest::blocking::RequestBuilder {
    client
        .post(TIMETABLE_URL)
        .form(&[("ZC", ""), ("XNXQDM", term), ("XH", ""), ("XQDM", "")])
        .header("Cookie", cookie)
        .header("Accept", "application/json, text/javascript, */*; q=0.01")
        .header("X-Requested-With", "XMLHttpRequest")
        .header("Referer", TIMETABLE_REFERER)
}

/// Book the follow-up read slot under the shared governor. A cooldown is a
/// durable refusal; pacing sleeps before transmission, never during a CAS
/// redirect chain (handled inside the authentication itself).
fn admit_session_read(lease: &mut RequestLease<'_>) -> Result<(), Error> {
    let reservation = lease
        .reserve_followup()
        .map_err(|_| error("governor_error", "cannot admit timetable follow-up"))?;
    if !reservation.cooldown_wait.is_zero() {
        return Err(error(
            "cooldown",
            "timetable authentication was deferred; no read or retry was sent",
        ));
    }
    if !reservation.request_wait.is_zero() {
        std::thread::sleep(reservation.request_wait);
    }
    Ok(())
}

fn with_provenance(mut output: Value, network: bool) -> Value {
    output["service"] = json!("gsmis");
    output["source"] = json!(if network { "network" } else { "disabled" });
    output["network_performed"] = json!(network);
    output["write_operations_performed"] = json!(false);
    output
}

/// A degraded read result carries the unmodified body as private caller-owned
/// evidence. It is only emitted after the credential echo and challenge
/// screens have cleared the body.
fn degraded(status: u16, content_type: Option<&str>, bytes: &[u8], reason: &'static str) -> Value {
    json!({
        "schema_version": 1,
        "type": "timetable_pg",
        "result": "degraded",
        "fallback_reason": reason,
        "http_status": status,
        "content_type": content_type,
        "raw_response_base64": STANDARD.encode(bytes),
        "raw_response_sha256": format!("{:x}", Sha256::digest(bytes)),
        "body_byte_length": bytes.len(),
    })
}

/// A withheld read result retains only safe metadata: no body bytes and only a
/// reviewed MIME essence, never the full Content-Type parameters.
fn withheld(status: u16, content_type: Option<&str>, bytes: &[u8], reason: &'static str) -> Value {
    let essence = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'+' | b'-' | b'_')
                })
        });
    json!({
        "schema_version": 1,
        "type": "timetable_pg",
        "result": "sensitive_response_withheld",
        "fallback_reason": reason,
        "http_status": status,
        "raw_evidence_withheld": true,
        "content_type": essence,
        "content_type_parameters_withheld": content_type.is_some_and(|value| Some(value) != essence),
        "body_byte_length": bytes.len(),
        "raw_response_sha256": format!("{:x}", Sha256::digest(bytes)),
    })
}

fn contains_cookie(bytes: &[u8], cookie: &str) -> bool {
    net::carries_secret(bytes, cookie)
        || cookie
            .split(';')
            .filter_map(|part| part.split_once('='))
            .any(|(_, value)| {
                let value = value.trim();
                net::carries_secret(bytes, value)
                    || value
                        .strip_prefix('"')
                        .and_then(|inner| inner.strip_suffix('"'))
                        .is_some_and(|unquoted| net::carries_secret(bytes, unquoted))
            })
}

/// JSON escapes hide a credential echo from a raw-byte scan; inspect decoded
/// strings and scalar re-encodings inside a parsed body.
fn value_contains_secret(value: &Value, contains: &dyn Fn(&[u8]) -> bool) -> bool {
    match value {
        Value::String(text) => contains(text.as_bytes()),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_secret(value, contains)),
        Value::Object(fields) => fields
            .values()
            .any(|value| value_contains_secret(value, contains)),
        Value::Number(_) | Value::Bool(_) | Value::Null => {
            net::json_scalar_matches(value, contains)
        }
    }
}

/// A recognized JSON session denial is authoritative even when its shape is
/// otherwise unadmitted: the read never presents it as timetable data.
fn session_denied(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let message = value
        .get("message")
        .or_else(|| value.get("msg"))
        .or_else(|| value.get("m"))
        .and_then(Value::as_str)
        .unwrap_or("");
    ["登录失效", "请重新登录", "未登录"]
        .iter()
        .any(|marker| message.contains(marker))
}

/// Header and body facts the response-backed read has already established.
/// The caller derives them from the response headers, the transmitted cookie
/// and the issued session jar; they never carry secret material themselves.
#[derive(Default)]
struct ReadScreening {
    /// The response re-issued session material, so its body is not exportable.
    issued_session_cookie: bool,
    /// A challenge signal was present in the response headers.
    header_challenge: bool,
    /// The declared Content-Type itself echoes credential material.
    metadata_echo: bool,
    /// The body, raw or JSON-decoded, echoes credential material.
    echo: bool,
}

/// The value one read body is admitted as, plus the denial signal the governor
/// records for it.
struct ReadAdmission {
    output: Value,
    denied: bool,
}

/// Screen one completely read, in-limit response body. This is pure: it
/// performs no I/O, no retry and no parsing of the request. A recognized
/// session denial is refused before the parser is consulted, so a denial body
/// can never be presented as timetable rows, and every non-2xx, non-UTF-8 or
/// unparsable body keeps byte-exact degraded evidence (base64, sha256,
/// Content-Type, reason and status) instead of an empty schedule.
fn admit_read_body(
    status: u16,
    content_type: Option<&str>,
    bytes: &[u8],
    term: &str,
    assessment: crate::html::ChallengeAssessment,
    screening: ReadScreening,
) -> ReadAdmission {
    let header_challenge = screening.header_challenge;
    let challenge = header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
    let safe_content_type = if screening.metadata_echo {
        None
    } else {
        content_type
    };
    let denied = !screening.echo && session_denied(bytes);
    let output = if screening.issued_session_cookie {
        // The read response may not re-issue session material; the MIME
        // essence itself can echo the issued value, so withhold it too.
        let mut output = withheld(status, None, bytes, "session_cookie_issued");
        output["content_type_parameters_withheld"] = json!(content_type.is_some());
        output
    } else if screening.echo {
        withheld(status, safe_content_type, bytes, "credential_echo")
    } else if assessment == crate::html::ChallengeAssessment::Unreviewed && !challenge {
        withheld(
            status,
            safe_content_type,
            bytes,
            "response_safety_unreviewed",
        )
    } else if challenge {
        let mut output = withheld(status, safe_content_type, bytes, "challenge_requires_human");
        output["challenge_required"] = json!(true);
        output
    } else if denied {
        let mut output = withheld(status, safe_content_type, bytes, "session_expired");
        output["result"] = json!("session_expired");
        output
    } else if !(200..300).contains(&status) {
        degraded(
            status,
            safe_content_type,
            bytes,
            "http_status_unsafe_response",
        )
    } else {
        match std::str::from_utf8(bytes) {
            Err(_) => degraded(status, safe_content_type, bytes, "utf8_decode_failed"),
            Ok(body) => {
                let mut output = crate::timetable_pg::parse_timetable(body, term);
                if output.get("result").and_then(Value::as_str) == Some("fallback") {
                    output["content_type"] = json!(safe_content_type);
                    output["http_status"] = json!(status);
                }
                output
            }
        }
    };
    ReadAdmission { output, denied }
}

/// One explicit in-memory CAS login to the graduate timetable service followed
/// by exactly one `loadXskbData.do` read. The session never persists, refreshes
/// or retries; the issued cookie is used for the single read only.
pub fn session(input: &str, online: bool) -> Result<Value, Error> {
    session_with_network(input, online, || {
        Ok((
            cas::http_client()?,
            Governor::open()
                .map_err(|_| error("governor_error", "shared request admission unavailable"))?,
        ))
    })
}

pub(crate) fn session_with_network(
    input: &str,
    online: bool,
    network: impl FnOnce() -> Result<(Client, Governor), Error>,
) -> Result<Value, Error> {
    if input.len() > SESSION_MAX_INPUT {
        return Err(session_invalid());
    }
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let input: SessionInput =
        deserialize_object(&mut deserializer).map_err(|_| session_invalid())?;
    deserializer.end().map_err(|_| session_invalid())?;
    if !input.read.enabled {
        return Ok(with_provenance(json!({"result": "disabled"}), false));
    }
    if !valid_term_code(&input.read.xnxqdm) {
        return Err(session_invalid());
    }
    if !input.authorized {
        return Err(error(
            "permission",
            "explicit authorization for one GSMIS authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if *input.intent != format!("LOGIN {} timetable", &*input.username) {
        return Err(session_invalid());
    }
    if !online {
        return Err(error(
            "online_required",
            "timetable sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let (client, governor) = network()?;
    let mut lease = net::acquire_kind(&governor, RequestKind::Authentication)?;
    let prepared = cas::authenticate_service(&mut lease, &client, CasService::Gsmis, credentials)
        .and_then(|session| {
            let url = url::Url::parse(TIMETABLE_URL).map_err(|_| session_invalid())?;
            let (cookie, expiry) = session.cookie_header(&url)?;
            let cookie = cookie.ok_or_else(|| {
                error(
                    "auth_latched",
                    "the timetable session cookie is missing; no read was sent",
                )
            })?;
            let builder = xskb_request(&client, &cookie, &input.read.xnxqdm);
            let mut request = builder
                .timeout(std::time::Duration::from_secs(45))
                .header("Accept-Encoding", "identity")
                .build()
                .map_err(|_| session_invalid())?;
            if let Some(value) = request.headers_mut().get_mut("cookie") {
                value.set_sensitive(true);
            }
            admit_session_read(&mut lease)?;
            Ok((session, cookie, expiry, request))
        });
    let (session, cookie, cookie_expiry, request) = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            if matches!(
                failure.code,
                "governor_error" | "governor_denied" | "governor_unavailable"
            ) {
                // Persistence failure after a send is not a local refusal.
                // Drop without finishing: retain the pending outcome for review.
                return Err(failure);
            }
            let settled = match failure.code {
                "auth_latched" => lease.finish(Outcome::CredentialRejected),
                "challenge_requires_human" => lease.finish(Outcome::CaptchaRequired),
                "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
                _ => lease.finish_without_request(),
            };
            settled.map_err(|_| {
                error(
                    "governor_error",
                    "cannot settle timetable authentication attempt",
                )
            })?;
            return Err(failure);
        }
    };
    // The one-shot read guards on the transmitted cookie and the issued jar:
    // a response that echoes either is withheld, never base64-exported.
    let contains = |candidate: &[u8]| {
        net::carries_secret(candidate, &input.username)
            || net::carries_secret(candidate, &input.password)
            || contains_cookie(candidate, &cookie)
            || session.contains_secret_bytes(candidate)
    };
    let mut response = match lease.start_request(|| {
        if cookie_expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
            None
        } else {
            Some(client.execute(request))
        }
    }) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) => {
            lease
                .finish(Outcome::NetworkFailure)
                .map_err(|_| error("governor_error", "cannot settle timetable request"))?;
            return Err(error(
                "network_error",
                "timetable request failed; no automatic retry",
            ));
        }
        Ok(None) => {
            lease
                .finish_without_request()
                .map_err(|_| error("governor_error", "cannot release timetable request"))?;
            return Err(error(
                "scoped_cookie_unusable",
                "the timetable cookie expired before transmission; no further request was sent",
            ));
        }
        Err(crate::governor::FollowupError::Governor(_)) => {
            return Err(error(
                "governor_error",
                "request safety admission failed; pending outcome retained",
            ));
        }
    };
    let status = response.status().as_u16();
    let issues_session_cookie = net::issues_session_cookie(response.headers());
    let retry_after = response
        .headers()
        .get_all("retry-after")
        .iter()
        .find_map(|value| value.to_str().ok())
        .map(str::to_owned);
    let content_types = response.headers().get_all("content-type");
    let mut content_types = content_types.iter();
    let content_type = match (content_types.next(), content_types.next()) {
        (Some(value), None) => value.to_str().ok().map(str::to_owned),
        _ => None,
    };
    let header_challenge = response
        .headers()
        .iter()
        .any(|(name, value)| net::challenge_header(name.as_str(), value.as_bytes()));
    // Commit header facts before consuming a body that may fail or be cut short.
    lease
        .observe_http_many(
            status,
            response
                .headers()
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            header_challenge,
        )
        .map_err(|_| {
            error(
                "governor_error",
                "cannot persist timetable response headers",
            )
        })?;
    let mut bytes = Zeroizing::new(Vec::new());
    let read_result = response
        .by_ref()
        .take(SESSION_BODY_LIMIT + 1)
        .read_to_end(&mut bytes);
    let incomplete = read_result.is_err() || bytes.len() as u64 > SESSION_BODY_LIMIT;
    let assessment =
        crate::html::assess_challenge_body(&bytes, content_type.as_deref(), !incomplete);
    let challenge = header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
    let metadata_echo = content_type
        .as_deref()
        .is_some_and(|value| contains(value.as_bytes()));
    let echo = contains(&bytes)
        || metadata_echo
        || std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .is_some_and(|value| value_contains_secret(&value, &contains));
    let mut denied = false;
    let result = if read_result.is_err() {
        Err(error(
            "network_error",
            "timetable response body read failed",
        ))
    } else if bytes.len() as u64 > SESSION_BODY_LIMIT {
        Err(error(
            "body_limit",
            "timetable response exceeds bounded body limit",
        ))
    } else {
        let admission = admit_read_body(
            status,
            content_type.as_deref(),
            &bytes,
            &input.read.xnxqdm,
            assessment,
            ReadScreening {
                issued_session_cookie: issues_session_cookie,
                header_challenge,
                metadata_echo,
                echo,
            },
        );
        denied = admission.denied;
        Ok(admission.output)
    };
    drop(response);
    if denied {
        lease
            .finish(Outcome::CredentialRejected)
            .map_err(|_| error("governor_error", "cannot settle timetable session denial"))?;
    } else {
        lease
            .finish(Outcome::Http {
                status,
                retry_after: retry_after.as_deref(),
                challenge,
                network_failure: incomplete,
            })
            .map_err(|_| error("governor_error", "cannot settle timetable request"))?;
    }
    result.map(|output| with_provenance(output, true))
}

/// Describe the command's input/output contract for `buaa schema`.
pub fn schema() -> Value {
    let mut schema = json!({
        "command": "timetable ics",
        "description": "Offline conversion of a semester schedule to a standards-compliant RFC 5545 ICS document. No network access, no writes.",
        "input": {
            "semester": {
                "start_date": "YYYY-MM-DD; the date of week 1, day Monday",
                "weeks": "total semester weeks (1..=104)"
            },
            "courses": [
                {
                    "name": "non-empty string",
                    "day": "weekday: monday..sunday (or mon..sun)",
                    "start_week": "1-based first week",
                    "end_week": "1-based last week (>= start_week); occurrences past the semester end are dropped",
                    "parity": "optional: all (default) | odd | even",
                    "start_time": "HH:MM",
                    "end_time": "HH:MM, after start_time",
                    "location": "optional string"
                }
            ]
        },
        "output": {
            "type": "timetable_ics",
            "event_count": "number of VEVENT instances",
            "ics": "RFC 5545 document text (CRLF line endings, 75-octet folding, floating local date-times)"
        }
    });
    schema["session"] = json!({
        "description": "One explicit in-memory CAS login to GSMIS followed by exactly one loadXskbData.do read; no persistence, refresh, retry, writes or cookie adoption.",
        "input": {
            "type": "object",
            "additionalProperties": false,
            "required": ["authorized", "username", "password", "intent", "read"],
            "properties": {
                "authorized": {"type": "boolean"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "intent": {"type": "string"},
                "read": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["operation", "enabled", "xnxqdm"],
                    "properties": {
                        "operation": {"const": "xskb"},
                        "enabled": {"type": "boolean"},
                        "xnxqdm": {"type": "string", "pattern": "^[0-9]{5}$"}
                    }
                }
            }
        },
        "intent": "LOGIN <username> timetable",
        "read_url": TIMETABLE_URL,
        "read_method": "POST form ZC=&XNXQDM={term}&XH=&XQDM=",
        "output": "timetable_pg parsed shape, or result degraded/fallback with raw_response_base64+raw_response_sha256+content_type+fallback_reason+http_status for a non-2xx, non-UTF-8 or unparsable body that clears the safety screens, or sensitive_response_withheld when credential/challenge/cookie material or an unreviewed body is detected, or result session_expired (evidence withheld) when the body is a recognized login denial and no rows are emitted; plus service, source, network_performed, write_operations_performed",
        "validation": "object root only; disabled read performs no I/O; enabled read requires authorized=true, exact intent, five-ASCII-digit xnxqdm and --online before transport or admission"
    });
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str) -> Value {
        check(input)
    }

    #[test]
    fn date_math_round_trips_and_weekdays() {
        // 2024-01-01 was a Monday.
        assert_eq!(weekday_monday_index(parse_date("2024-01-01").unwrap()), 0);
        // 2026-09-21 is a Monday.
        assert_eq!(weekday_monday_index(parse_date("2026-09-21").unwrap()), 0);
        // Round-trip a spread of dates through civil_from_days.
        for date in [
            "1970-01-01",
            "2000-02-29",
            "2026-09-21",
            "2027-01-04",
            "1999-12-31",
        ] {
            let z = parse_date(date).unwrap();
            let (y, m, d) = civil_from_days(z);
            assert_eq!(format!("{:04}-{:02}-{:02}", y, m, d), date);
        }
    }

    #[test]
    fn invalid_dates_and_times_are_rejected() {
        for bad in [
            "2026-13-01",
            "2026-02-29",
            "2026-9-21",
            "2026/09/21",
            "20260921",
            "2026-02-30",
        ] {
            assert!(parse_date(bad).is_none(), "accepted {bad}");
        }
        assert!(parse_time("24:00").is_none());
        assert!(parse_time("08:60").is_none());
        assert!(parse_time("8:00").is_none());
        assert_eq!(parse_time("08:00"), Some((8, 0)));
    }

    #[test]
    fn monday_course_maps_to_expected_week_dates() {
        // Semester starts Monday 2026-09-21, 16 weeks. A Monday course in
        // weeks 1..=16 yields one occurrence per week.
        let input = r#"{
            "semester": {"start_date": "2026-09-21", "weeks": 16},
            "courses": [{
                "name": "Linear Algebra",
                "day": "monday",
                "start_week": 1,
                "end_week": 16,
                "start_time": "08:00",
                "end_time": "09:40"
            }]
        }"#;
        let out = run(input);
        assert!(out.get("error").is_none(), "{out}");
        assert_eq!(out["event_count"], 16);
        let ics = out["ics"].as_str().unwrap();
        // Independently computed: week 1 -> 2026-09-21, week 2 -> 2026-09-28,
        // week 16 -> 2027-01-04.
        assert!(ics.contains("DTSTART:20260921T080000"));
        assert!(ics.contains("DTSTART:20260928T080000"));
        assert!(ics.contains("DTSTART:20270104T080000"));
        assert!(ics.contains("DTEND:20260921T094000"));
    }

    #[test]
    fn odd_parity_drops_even_weeks() {
        let input = r#"{
            "semester": {"start_date": "2026-09-21", "weeks": 8},
            "courses": [{
                "name": "Lab",
                "day": "tuesday",
                "start_week": 1,
                "end_week": 8,
                "parity": "odd",
                "start_time": "14:00",
                "end_time": "16:00"
            }]
        }"#;
        let out = run(input);
        assert_eq!(out["event_count"], 4); // weeks 1,3,5,7
        let ics = out["ics"].as_str().unwrap();
        // Week 1 Tuesday = 2026-09-22; week 2 Tuesday (2026-09-29) is dropped.
        assert!(ics.contains("DTSTART:20260922T140000"));
        assert!(!ics.contains("DTSTART:20260929T140000"));
    }

    #[test]
    fn occurrences_past_the_semester_are_dropped() {
        // 4-week semester starting Monday 2026-09-21; last day is
        // 2026-09-21 + 28 - 1 = 2026-10-18. A course scheduled through week 6
        // must be truncated to the four weeks that exist.
        let input = r#"{
            "semester": {"start_date": "2026-09-21", "weeks": 4},
            "courses": [{
                "name": "Study",
                "day": "monday",
                "start_week": 1,
                "end_week": 6,
                "start_time": "10:00",
                "end_time": "11:00"
            }]
        }"#;
        let out = run(input);
        assert!(out.get("error").is_none(), "{out}");
        assert_eq!(
            out["event_count"], 4,
            "weeks 5-6 are past the semester and must be dropped"
        );
        let ics = out["ics"].as_str().unwrap();
        // Week 4 (2026-10-12) is the last in-range Monday...
        assert!(ics.contains("DTSTART:20261012T100000"));
        // ...and week 5 (2026-10-19) is past the semester end (2026-10-18).
        assert!(!ics.contains("DTSTART:20261019T100000"));
    }

    #[test]
    fn ics_is_standards_compliant() {
        let input = r#"{
            "semester": {"start_date": "2026-09-21", "weeks": 2},
            "courses": [{
                "name": "Course, with; special chars",
                "day": "wednesday",
                "start_week": 1,
                "end_week": 2,
                "start_time": "09:00",
                "end_time": "10:30",
                "location": "Hall 3, Room 2"
            }]
        }"#;
        let out = run(input);
        let ics = out["ics"].as_str().unwrap();
        // CRLF line endings, no bare LF.
        assert!(ics.contains("\r\n"));
        assert!(!ics.replace("\r\n", "").contains('\n'));
        // Wrapped in a VCALENDAR.
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ics.ends_with("END:VCALENDAR"));
        // Required VEVENT properties present.
        for prop in [
            "VERSION:2.0",
            "PRODID:",
            "CALSCALE:GREGORIAN",
            "BEGIN:VEVENT",
            "UID:",
            "DTSTAMP:",
            "DTSTART:",
            "DTEND:",
            "SUMMARY:",
            "LOCATION:",
            "END:VEVENT",
        ] {
            assert!(ics.contains(prop), "missing {prop}");
        }
        // Text escaping of comma and semicolon.
        assert!(ics.contains("SUMMARY:Course\\, with\\; special chars"));
        assert!(ics.contains("LOCATION:Hall 3\\, Room 2"));
        // Every physical line <= 75 octets (excluding CRLF).
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "line too long ({}): {line}", line.len());
        }
    }

    #[test]
    fn long_summary_is_folded_on_char_boundaries() {
        // A 200-char summary forces folding; ensure no line exceeds 75 octets
        // and the un-folded content is reconstructable.
        let long_name = "x".repeat(200);
        let input = serde_json::to_string(&json!({
            "semester": {"start_date": "2026-09-21", "weeks": 1},
            "courses": [{
                "name": long_name,
                "day": "monday",
                "start_week": 1,
                "end_week": 1,
                "start_time": "08:00",
                "end_time": "09:00"
            }]
        }))
        .unwrap();
        let out = run(&input);
        assert!(out.get("error").is_none(), "{out}");
        let ics = out["ics"].as_str().unwrap();
        for line in ics.split("\r\n") {
            assert!(line.len() <= 75, "line too long: {line}");
        }
        // The SUMMARY logical line is folded: the first physical line has no
        // leading space; each continuation line starts with one space, which
        // is removed when unfolding. Re-unfolding must recover the value.
        let lines: Vec<&str> = ics.split("\r\n").collect();
        let start = lines
            .iter()
            .position(|line| line.starts_with("SUMMARY:"))
            .unwrap();
        let mut unfolded = lines[start].to_string();
        let mut i = start + 1;
        while i < lines.len() && lines[i].starts_with(' ') {
            unfolded.push_str(&lines[i][1..]);
            i += 1;
        }
        assert_eq!(unfolded, format!("SUMMARY:{long_name}"));
    }

    #[test]
    fn invalid_input_is_rejected() {
        for bad in ["not json", "{}"] {
            let out = run(bad);
            assert_eq!(out["error"], "invalid_input", "{out}");
        }
        // Missing required course field.
        let out = run(r#"{
                "semester": {"start_date": "2026-09-21", "weeks": 2},
                "courses": [{"name":"A","day":"monday","start_week":1,"end_week":2,"start_time":"08:00"}]
            }"#);
        assert_eq!(out["error"], "invalid_input");
        assert!(out["message"].as_str().unwrap().contains("end_time"));
        // start_week after end_week.
        let out = run(r#"{
                "semester": {"start_date": "2026-09-21", "weeks": 2},
                "courses": [{"name":"A","day":"monday","start_week":3,"end_week":2,"start_time":"08:00","end_time":"09:00"}]
            }"#);
        assert_eq!(out["error"], "invalid_input");
        // end before start.
        let out = run(r#"{
                "semester": {"start_date": "2026-09-21", "weeks": 2},
                "courses": [{"name":"A","day":"monday","start_week":1,"end_week":2,"start_time":"09:00","end_time":"08:00"}]
            }"#);
        assert_eq!(out["error"], "invalid_input");
    }

    #[test]
    fn empty_courses_is_valid_with_zero_events() {
        let out = run(r#"{"semester":{"start_date":"2026-09-21","weeks":16},"courses":[]}"#);
        assert!(out.get("error").is_none(), "{out}");
        assert_eq!(out["event_count"], 0);
    }
}

// These fixed synthetic scenarios stop before transport and governor work.
#[cfg(test)]
mod session_tests {
    use super::*;

    fn session_input() -> Value {
        json!({
            "authorized": true,
            "username": "synthetic-operator-4b7",
            "password": "synthetic-password-9q2",
            "intent": "LOGIN synthetic-operator-4b7 timetable",
            "read": {"operation": "xskb", "enabled": true, "xnxqdm": "20261"}
        })
    }

    #[test]
    fn intent_mismatch_is_refused_before_io() {
        let mut request = session_input();
        request["intent"] = json!("LOGIN another-operator timetable");
        let failure = session_with_network(&request.to_string(), true, || {
            panic!("intent mismatch opened network resources")
        })
        .unwrap_err();
        assert_eq!(failure.code, "invalid_input");
        // The intent binds the same username, not merely the constant suffix.
        let mut bound = session_input();
        bound["intent"] = json!("LOGIN synthetic-operator-4b7 smart exams");
        let failure = session_with_network(&bound.to_string(), true, || {
            panic!("cross-service intent opened network resources")
        })
        .unwrap_err();
        assert_eq!(failure.code, "invalid_input");
    }

    #[test]
    fn xnxqdm_shape_is_refused_before_io() {
        for (term, label) in [
            ("2026", "too short"),
            ("202612", "too long"),
            ("2026x", "non-digit"),
            ("2026 ", "trailing space"),
            ("２０２６１", "non-ascii digits"),
        ] {
            let mut request = session_input();
            request["read"]["xnxqdm"] = json!(term);
            let failure = session_with_network(&request.to_string(), true, || {
                panic!("invalid xnxqdm {label} opened network resources")
            })
            .unwrap_err();
            assert_eq!(failure.code, "invalid_input", "{label}");
        }
        // A non-object read or unknown operation fails at the object boundary.
        for (read, label) in [
            (json!("xskb"), "non-object read"),
            (
                json!({"operation": "terms", "enabled": true, "xnxqdm": "20261"}),
                "unknown operation",
            ),
            (
                json!({"operation": "xskb", "xnxqdm": "20261"}),
                "missing enabled",
            ),
        ] {
            let mut request = session_input();
            request["read"] = read;
            let failure = session_with_network(&request.to_string(), true, || {
                panic!("{label} opened network resources")
            })
            .unwrap_err();
            assert_eq!(failure.code, "invalid_input", "{label}");
        }
    }

    #[test]
    fn disabled_read_performs_no_io() {
        let mut request = session_input();
        request["read"]["enabled"] = json!(false);
        // Disabled refuses before any credential, intent or term validation.
        request["authorized"] = json!(false);
        request["username"] = json!("");
        request["password"] = json!("");
        request["intent"] = json!("");
        request["read"]["xnxqdm"] = json!("bad");
        let output = session_with_network(&request.to_string(), true, || {
            panic!("disabled read opened network resources")
        })
        .unwrap();
        assert_eq!(output["result"], "disabled");
        assert_eq!(output["source"], "disabled");
        assert_eq!(output["network_performed"], false);
        assert_eq!(output["write_operations_performed"], false);
    }

    #[test]
    fn unapproved_reads_never_open_authentication_resources() {
        let mut unauthorized = session_input();
        unauthorized["authorized"] = json!(false);
        let failure = session_with_network(&unauthorized.to_string(), true, || {
            panic!("unauthorized read opened authentication resources")
        })
        .unwrap_err();
        assert_eq!(failure.code, "permission");
        let failure = session_with_network(&session_input().to_string(), false, || {
            panic!("offline session opened authentication resources")
        })
        .unwrap_err();
        assert_eq!(failure.code, "online_required");
    }

    /// Synthesized GSMIS `loadXskbData.do` envelope with one scheduled row.
    /// Every value here is a fixture; nothing is derived from a real response.
    fn timetable_body() -> Value {
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

    fn complete_assessment(
        content_type: Option<&str>,
        body: &[u8],
    ) -> crate::html::ChallengeAssessment {
        crate::html::assess_challenge_body(body, content_type, true)
    }

    /// Degraded evidence must be bound to the exact bytes and must never be
    /// accompanied by a schedule.
    fn assert_byte_exact_evidence(output: &Value, body: &[u8], digest: &str) {
        let encoded = output["raw_response_base64"].as_str().unwrap();
        assert_eq!(encoded, STANDARD.encode(body));
        assert_eq!(STANDARD.decode(encoded).unwrap(), body);
        assert_eq!(output["raw_response_sha256"], digest);
        assert_eq!(output["body_byte_length"], body.len());
        for key in [
            "calendar",
            "event_count",
            "ics",
            "normalized",
            "schedule_row_count",
            "semester_start",
        ] {
            assert!(output.get(key).is_none(), "{key} emitted: {output}");
        }
    }

    #[test]
    fn non_json_body_is_degraded_with_exact_evidence() {
        let body = b"<html><body>unexpected upstream page</body></html>";
        let content_type = Some("text/html; charset=utf-8");
        // Precondition: the page carries no challenge control, so it is
        // screened as Clear and reaches the parser rather than a withholding.
        assert_eq!(
            complete_assessment(content_type, body),
            crate::html::ChallengeAssessment::Clear
        );
        let admission = admit_read_body(
            200,
            content_type,
            body,
            "20261",
            complete_assessment(content_type, body),
            ReadScreening::default(),
        );
        assert!(!admission.denied);
        let output = &admission.output;
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["type"], "timetable_pg");
        assert_eq!(output["fallback_reason"], "invalid_json");
        assert_eq!(output["http_status"], 200);
        assert_eq!(output["content_type"], "text/html; charset=utf-8");
        assert_byte_exact_evidence(
            output,
            body,
            "2a08126e5971c80a0e2ff3c9c2589e7773da9c021e8c6cab4cb2d7d59345b603",
        );
    }

    #[test]
    fn non_utf8_body_is_degraded_with_exact_evidence() {
        let body: &[u8] = b"\x89PNG\r\n\x1a\n\xff\xfe";
        let content_type = Some("application/octet-stream");
        assert_eq!(
            complete_assessment(content_type, body),
            crate::html::ChallengeAssessment::Clear
        );
        let admission = admit_read_body(
            200,
            content_type,
            body,
            "20261",
            complete_assessment(content_type, body),
            ReadScreening::default(),
        );
        let output = &admission.output;
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "utf8_decode_failed");
        assert_eq!(output["http_status"], 200);
        assert_eq!(output["content_type"], "application/octet-stream");
        assert_byte_exact_evidence(
            output,
            body,
            "608b46bb11fb3fd7be889e6e75fb4deee0ea15be13ad778fef9d04007828b877",
        );
    }

    #[test]
    fn unsafe_status_body_is_degraded_with_exact_evidence() {
        let body = br#"{"code":-1,"error":"synthetic upstream failure"}"#;
        let content_type = Some("application/json");
        assert_eq!(
            complete_assessment(content_type, body),
            crate::html::ChallengeAssessment::Clear
        );
        let admission = admit_read_body(
            500,
            content_type,
            body,
            "20261",
            complete_assessment(content_type, body),
            ReadScreening::default(),
        );
        let output = &admission.output;
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["fallback_reason"], "http_status_unsafe_response");
        assert_eq!(output["http_status"], 500);
        assert_eq!(output["content_type"], "application/json");
        assert_byte_exact_evidence(
            output,
            body,
            "ea88af9b744f083d937e256d5743cec0a480796251b4b043c00eca3f74b09e67",
        );
        // The same bytes are a parseable schedule at HTTP 200, but a 2xx
        // check alone must never turn a non-2xx status into rows.
        let payload = timetable_body().to_string();
        assert_eq!(
            crate::timetable_pg::parse_timetable(&payload, "20261")["result"],
            "parsed"
        );
        let unsafe_payload = admit_read_body(
            503,
            content_type,
            payload.as_bytes(),
            "20261",
            complete_assessment(content_type, payload.as_bytes()),
            ReadScreening::default(),
        );
        assert_eq!(unsafe_payload.output["result"], "degraded");
        assert_eq!(
            unsafe_payload.output["fallback_reason"],
            "http_status_unsafe_response"
        );
        let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
        assert_byte_exact_evidence(&unsafe_payload.output, payload.as_bytes(), &digest);
    }

    #[test]
    fn session_denial_never_emits_rows() {
        let mut payload = timetable_body();
        payload["message"] = json!("登录失效，请重新登录");
        let body = payload.to_string();
        // The bytes are a complete, parseable timetable payload on their own,
        // so only the denial screen can keep rows out of the output.
        assert_eq!(
            crate::timetable_pg::parse_timetable(&body, "20261")["result"],
            "parsed"
        );
        assert!(session_denied(body.as_bytes()));
        let content_type = Some("application/json");
        let admission = admit_read_body(
            200,
            content_type,
            body.as_bytes(),
            "20261",
            complete_assessment(content_type, body.as_bytes()),
            ReadScreening::default(),
        );
        assert!(admission.denied);
        let output = &admission.output;
        assert_eq!(output["result"], "session_expired");
        assert_eq!(output["fallback_reason"], "session_expired");
        assert_eq!(output["raw_evidence_withheld"], true);
        for key in [
            "calendar",
            "event_count",
            "ics",
            "normalized",
            "raw_response_base64",
            "schedule_row_count",
            "semester_start",
        ] {
            assert!(output.get(key).is_none(), "{key} emitted: {output}");
        }
        // A denial that also echoes credential material is withheld instead,
        // and still never reaches the parser.
        let echoing = admit_read_body(
            200,
            content_type,
            body.as_bytes(),
            "20261",
            complete_assessment(content_type, body.as_bytes()),
            ReadScreening {
                echo: true,
                ..ReadScreening::default()
            },
        );
        assert!(!echoing.denied);
        assert_eq!(echoing.output["result"], "sensitive_response_withheld");
        assert_eq!(echoing.output["fallback_reason"], "credential_echo");
        for key in ["calendar", "event_count", "schedule_row_count"] {
            assert!(echoing.output.get(key).is_none(), "{key} emitted");
        }
    }

    /// The module's synthetic session fixture with one term substituted.
    fn term_request(term: &str) -> String {
        let mut request = session_input();
        request["read"]["xnxqdm"] = json!(term);
        request.to_string()
    }

    #[test]
    fn five_digit_term_accepted_while_other_lengths_are_refused() {
        for term in ["20261", "20253", "00000"] {
            assert!(valid_term_code(term), "{term}");
        }
        for term in ["2026", "202612", "202611", "2026x", "20261 ", "", "2026１"] {
            assert!(!valid_term_code(term), "{term}");
        }
        // Only the five-digit shape reaches the online gate; four- and
        // six-digit terms are refused before any credential or transport work.
        for term in ["2026", "202612"] {
            let failure = session_with_network(&term_request(term), true, || {
                panic!("refused term {term} opened network resources")
            })
            .unwrap_err();
            assert_eq!(failure.code, "invalid_input", "{term}");
        }
        for term in ["20261", "20253"] {
            let failure = session_with_network(&term_request(term), false, || {
                panic!("offline session opened network resources")
            })
            .unwrap_err();
            assert_eq!(failure.code, "online_required", "{term}");
        }
    }
}

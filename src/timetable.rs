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
//! followed by the current timetable application document, its
//! student-context initialization and exactly one `loadXskbData.do`
//! read in the same invocation. It
//! never retries, refreshes or caches, and credential material never leaves
//! the invocation. The GSMIS service re-issues its session cookie on the
//! read; those declarations are absorbed into the invocation's in-memory
//! jar and joined into the credential-echo screen, never persisted or
//! replayed.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

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
        .filter(|s| *s >= 1 && *s <= MAX_WEEKS as u64)
        .ok_or_else(|| {
            format!("course {index}: start_week must be an integer in 1..={MAX_WEEKS}")
        })? as u32;
    let end_week = get("end_week")?
        .as_u64()
        .filter(|s| *s >= 1 && *s <= MAX_WEEKS as u64)
        .ok_or_else(|| format!("course {index}: end_week must be an integer in 1..={MAX_WEEKS}"))?
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
// Graduate timetable session: one explicit in-memory CAS login to GSMIS,
// one application document, one student-context initialization and exactly
// one loadXskbData.do read. Secrets are stdin-only inputs; they are never
// persisted, logged or placed inside a generic Value tree. The read performs
// no writes, retries, refreshes or pagination. Session cookies issued by the
// application and read responses are absorbed into the same invocation-only
// jar and screened like every other credential, never exported or persisted.

const SESSION_BODY_LIMIT: u64 = 8 * 1024 * 1024;
const SESSION_MAX_INPUT: usize = 65536;
const TIMETABLE_PAGE_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/*default/index.do";
const TIMETABLE_PORTAL_URL: &str =
    "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do";
const TIMETABLE_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/bykb/loadXskbData.do";
const TIMETABLE_REFERER: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/*default/index.do";
const TIMETABLE_INIT_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdkbapp/wdkcb/initXsxx.do";

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

fn xskb_request(
    client: &Client,
    cookie: reqwest::header::HeaderValue,
    term: &str,
) -> reqwest::blocking::RequestBuilder {
    session_request(client, TIMETABLE_URL, cookie).form(&[
        ("ZC", ""),
        ("XNXQDM", term),
        ("XH", ""),
        ("XQDM", ""),
    ])
}

/// The live GSMIS application admits only its own student-context envelope.
/// Inspect shape and field identity, never export the returned account values.
fn student_context_present(bytes: &[u8]) -> Result<bool, Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = PrivateValue::deserialize(&mut de)
        .map_err(|_| error("upstream_parse", "timetable context is not strict JSON"))?;
    de.end()
        .map_err(|_| error("upstream_parse", "timetable context has trailing content"))?;
    let Some(rows) = value.0.get("data").and_then(Value::as_array) else {
        return Err(error(
            "upstream_parse",
            "timetable context has no data array",
        ));
    };
    for row in rows {
        let Some(row) = row.as_object() else {
            return Err(error(
                "upstream_parse",
                "timetable context row is not an object",
            ));
        };
        let Some(id) = row.get("XH").and_then(Value::as_str) else {
            return Err(error(
                "upstream_parse",
                "timetable context has no student identity field",
            ));
        };
        if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return Err(error(
                "upstream_parse",
                "timetable context identity is not admissible",
            ));
        }
    }
    Ok(!rows.is_empty())
}

fn session_request(
    client: &Client,
    url: &str,
    cookie: reqwest::header::HeaderValue,
) -> reqwest::blocking::RequestBuilder {
    client
        .post(url)
        .header("Cookie", cookie)
        .header("Accept", "application/json, text/javascript, */*; q=0.01")
        .header("X-Requested-With", "XMLHttpRequest")
        .header("Referer", TIMETABLE_REFERER)
}

struct ContextResponse {
    status: u16,
    retry_after: Option<String>,
    challenge: bool,
    content_type: Option<String>,
    body: Zeroizing<Vec<u8>>,
}

/// Persist response safety facts before any cookie or body processing can
/// fail, then absorb the reviewed same-origin cookie declarations and retain
/// a bounded body for the caller's challenge and credential-echo screens.
fn receive_context_response(
    response: Response,
    lease: &mut RequestLease<'_>,
    session: &mut cas::ServiceSession,
    url: &url::Url,
    observed: &mut Option<(u16, Option<String>, bool)>,
) -> Result<ContextResponse, Error> {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get_all("retry-after")
        .iter()
        .find_map(|value| value.to_str().ok())
        .map(str::to_owned);
    let challenge = response
        .headers()
        .iter()
        .any(|(name, value)| net::challenge_header(name.as_str(), value.as_bytes()));
    let content_type = match (
        response.headers().get_all("content-type").iter().next(),
        response.headers().get_all("content-type").iter().nth(1),
    ) {
        (Some(value), None) => value.to_str().ok().map(str::to_owned),
        _ => None,
    };
    *observed = Some((status, retry_after.clone(), challenge));
    lease
        .observe_http_many(
            status,
            response
                .headers()
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            challenge,
        )
        .map_err(|_| error("governor_error", "cannot persist timetable response"))?;
    session.absorb_gsmis_headers(url, response.headers())?;
    let mut body = Zeroizing::new(Vec::new());
    response
        .take(SESSION_BODY_LIMIT + 1)
        .read_to_end(&mut body)
        .map_err(|_| error("network_error", "timetable context body read failed"))?;
    if body.len() as u64 > SESSION_BODY_LIMIT {
        return Err(error(
            "body_limit",
            "timetable context exceeds its body limit",
        ));
    }
    Ok(ContextResponse {
        status,
        retry_after,
        challenge,
        content_type,
        body,
    })
}

fn screen_context_response(
    response: &ContextResponse,
    input: &SessionInput,
    session: &cas::ServiceSession,
    expected_identity_echo: bool,
) -> Result<(), Error> {
    let assessment =
        crate::html::assess_challenge_body(&response.body, response.content_type.as_deref(), true);
    if response.challenge || assessment == crate::html::ChallengeAssessment::Detected {
        return Err(error(
            "challenge_requires_human",
            "timetable context requires review",
        ));
    }
    // initXsxx returns the authenticated student's XH, normally the CAS
    // username. Its body is consumed only by student_context_present and is
    // never exported, so that expected identity is not an output echo. The
    // application document has no such exception; password and cookie
    // material remain refused at both steps.
    if (!expected_identity_echo && net::carries_secret(&response.body, &input.username))
        || net::carries_secret(&response.body, &input.password)
        || session.contains_secret_bytes(&response.body)
    {
        return Err(error(
            "credential_echo",
            "timetable context contains credential material",
        ));
    }
    match decoded_body_screening(&response.body, &|candidate: &[u8]| {
        (!expected_identity_echo && net::carries_secret(candidate, &input.username))
            || net::carries_secret(candidate, &input.password)
            || session.contains_secret_bytes(candidate)
    }) {
        BodyScreening::Clear => {}
        BodyScreening::Echo => {
            return Err(error(
                "credential_echo",
                "timetable context contains decoded credential material",
            ));
        }
        BodyScreening::Unreviewable => {
            return Err(error(
                "response_safety_unreviewed",
                "timetable context cannot be screened completely",
            ));
        }
    }
    Ok(())
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

/// Upper bound on the `Set-Cookie` declarations one read response can
/// contribute to the invocation-only jar, matching the shared session jar.
const MAX_ISSUED_COOKIES: usize = 64;

/// Session cookies issued by the single read response. They are retained
/// only so the credential-echo screen covers the newly issued material;
/// the read is terminal, so nothing is persisted or replayed. Values are
/// zeroized on drop. The complete `name=value` pair is retained alongside
/// the bare value: a composite spelling has different base64 boundaries
/// from the value alone, so screening only values would miss an encoded
/// full-pair echo (e.g. base64("sid=abc") is not base64("abc")).
#[derive(Default)]
struct IssuedCookies {
    entries: Vec<IssuedCookie>,
    complete: bool,
}

/// One absorbed cookie: the complete first `name=value` pair exactly as
/// issued, plus the unquoted composite spelling when the value was quoted.
/// The bare value is derived from the pair at screen time, not stored
/// separately.
struct IssuedCookie {
    /// Complete, trimmed first `name=value` pair exactly as issued.
    pair: Zeroizing<String>,
    /// A quoted cookie also has an unquoted composite spelling. Its base64
    /// boundaries differ from both the quoted pair and the bare value.
    unquoted_pair: Option<Zeroizing<String>>,
}

impl IssuedCookies {
    /// Absorb every `Set-Cookie` declaration the response carries. Each
    /// value is admitted through the same name/value review the CAS jar
    /// uses; declarations that are not valid UTF-8 or exceed the bound
    /// leave the jar incomplete so the body is withheld rather than
    /// exported unscreened. A declaration without a `=` pair, or with a
    /// name/value the review rejects, is equally unscreenable: skipping it
    /// would export a body whose credential material was never screened,
    /// so it also leaves the jar incomplete. An empty value (bare `=` or
    /// `=""`) deletes the cookie: it is not a secret and is not retained,
    /// so it can never false-positive against an arbitrary empty JSON field.
    fn absorb(headers: &reqwest::header::HeaderMap) -> Self {
        let mut jar = IssuedCookies {
            entries: Vec::new(),
            complete: true,
        };
        let declarations = headers.get_all(reqwest::header::SET_COOKIE);
        if declarations.iter().count() > MAX_ISSUED_COOKIES {
            jar.complete = false;
            return jar;
        }
        for declaration in declarations {
            let Ok(text) = declaration.to_str() else {
                jar.complete = false;
                continue;
            };
            let Some(pair) = text.split(';').next() else {
                jar.complete = false;
                continue;
            };
            let Some((name, value)) = pair.split_once('=') else {
                jar.complete = false;
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            if cas::valid_cookie_name(name) && cas::valid_cookie_value(value) {
                let unquoted = value
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'))
                    .unwrap_or(value);
                // An empty value deletes the cookie; it carries no secret.
                if unquoted.is_empty() {
                    continue;
                }
                // The complete pair is the first name=value segment only;
                // attributes (Path, HttpOnly, …) are not credential carriers.
                let pair = pair.trim();
                let unquoted_pair = if value.len() == unquoted.len() {
                    None
                } else {
                    Some(Zeroizing::new(format!("{name}={unquoted}")))
                };
                jar.entries.push(IssuedCookie {
                    pair: Zeroizing::new(pair.to_owned()),
                    unquoted_pair,
                });
            } else {
                jar.complete = false;
            }
        }
        jar
    }

    /// Whether the candidate bytes echo any issued cookie value, the
    /// complete `name=value` pair, or either in its unquoted spelling.
    fn contains_secret_bytes(&self, bytes: &[u8]) -> bool {
        self.entries.iter().any(|entry| {
            let value = entry
                .pair
                .split_once('=')
                .map(|(_, value)| value.trim())
                .expect("absorbed cookie pair contains equals");
            net::carries_secret(bytes, &entry.pair)
                || entry
                    .unquoted_pair
                    .as_ref()
                    .is_some_and(|pair| net::carries_secret(bytes, pair))
                || net::carries_secret(bytes, value)
                || value
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'))
                    .is_some_and(|unquoted| net::carries_secret(bytes, unquoted))
        })
    }
}

/// A `serde_json::Value` built by strict admission only: object members are
/// retained with their decoded names, duplicate members are rejected before
/// either occurrence can be dropped, and no positional spelling is silently
/// retyped. Drop wipes every retained string so decoded material never
/// outlives the screen.
struct PrivateValue(Value);
impl<'de> Deserialize<'de> for PrivateValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PrivateValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::String(value)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = PrivateValue(Value::Array(Vec::new()));
                while let Some(mut value) = access.next_element::<PrivateValue>()? {
                    result
                        .0
                        .as_array_mut()
                        .unwrap()
                        .push(std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = PrivateValue(Value::Object(serde_json::Map::new()));
                while let Some(key) = access.next_key::<String>()? {
                    let mut key = Zeroizing::new(key);
                    let values = result.0.as_object_mut().unwrap();
                    if values.contains_key(key.as_str()) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let mut value = access.next_value::<PrivateValue>()?;
                    values.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
impl std::ops::Deref for PrivateValue {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl Drop for PrivateValue {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}
fn wipe_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_value),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                wipe_value(&mut value);
            }
        }
        _ => {}
    }
}

/// JSON escapes hide a credential echo from a raw-byte scan; inspect every
/// decoded member name and string plus scalar re-encodings inside a
/// strictly admitted body.
fn value_contains_secret(value: &Value, contains: &dyn Fn(&[u8]) -> bool) -> bool {
    match value {
        Value::String(text) => contains(text.as_bytes()),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_secret(value, contains)),
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            contains(name.as_bytes()) || value_contains_secret(value, contains)
        }),
        Value::Number(_) | Value::Bool(_) | Value::Null => {
            net::json_scalar_matches(value, contains)
        }
    }
}

/// The outcome of screening one response body against every secret the
/// invocation holds. `Echo` is a definite credential match. `Unreviewable`
/// means part of the body could not be screened — an escaped JSON literal a
/// strict decoder rejects — so neither a definite echo nor safety was
/// established. `Clear` means every check ran to completion without a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyScreening {
    Clear,
    Echo,
    Unreviewable,
}

/// Screen every decoded string and member name one body produces. Strict
/// `PrivateValue` admission keeps duplicate members and decoded names in
/// scope for the credential check; bodies it rejects (duplicate keys,
/// malformed structure) fall back to decoding each escaped string literal
/// individually so an echo hidden behind a duplicate or an escape cannot
/// pass, while an escaped literal that cannot be decoded is unreviewable
/// rather than presumed safe.
fn decoded_body_screening(bytes: &[u8], contains: &dyn Fn(&[u8]) -> bool) -> BodyScreening {
    match serde_json::from_slice::<PrivateValue>(bytes) {
        Ok(value) => {
            if value_contains_secret(&value, contains) {
                BodyScreening::Echo
            } else {
                BodyScreening::Clear
            }
        }
        Err(_) => escaped_string_screening(bytes, contains),
    }
}

/// Screen JSON string spellings that only exist after decoding. A body that
/// fails strict `PrivateValue` parsing (a duplicate key, truncated
/// structure) can still encode a retained credential inside an escaped
/// string (`\u0061`, `\/`, `\\`), and the raw bytes never contain the
/// decoded spelling. Only literals that carry a JSON escape need decoding;
/// every unescaped spelling is already covered by the byte-level check. An
/// escaped literal that cannot be decoded — a string cut off before its
/// closing quote or an invalid escape — cannot be screened at all: a
/// lenient consumer may still recover a credential spelling from it, so it
/// is unreviewable rather than presumed safe or presumed an echo.
fn escaped_string_screening(bytes: &[u8], contains: &dyn Fn(&[u8]) -> bool) -> BodyScreening {
    let mut cursor = 0;
    let mut unreviewable = false;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let opening = cursor;
        cursor += 1;
        let mut escaped = false;
        let mut terminated = false;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => {
                    escaped = true;
                    cursor = cursor.saturating_add(2);
                }
                b'"' => {
                    terminated = true;
                    break;
                }
                _ => cursor += 1,
            }
        }
        if !terminated {
            // A cut-off literal carrying an escape is never presumed safe:
            // a lenient consumer may recover the credential spelling a
            // strict decoder rejects.
            unreviewable |= escaped;
            break;
        }
        if escaped {
            match serde_json::from_slice::<String>(&bytes[opening..=cursor]) {
                Ok(value) => {
                    let value = Zeroizing::new(value);
                    if contains(value.as_bytes()) {
                        return BodyScreening::Echo;
                    }
                }
                // An escaped literal that cannot be decoded cannot be
                // screened; record it and keep looking for a definite
                // echo, which outranks the unreviewable verdict.
                Err(_) => unreviewable = true,
            }
        }
        cursor += 1;
    }
    if unreviewable {
        BodyScreening::Unreviewable
    } else {
        BodyScreening::Clear
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
    /// A challenge signal was present in the response headers.
    header_challenge: bool,
    /// The declared Content-Type itself echoes credential material.
    metadata_echo: bool,
    /// The body, raw or JSON-decoded, echoes credential material.
    echo: bool,
    /// Part of the body could not be screened at all: an escaped JSON
    /// literal the decoder rejects, so neither echo nor safety was
    /// established.
    body_unreviewed: bool,
    /// The response's `Set-Cookie` declarations could not all be reviewed
    /// (over the bound, invalid UTF-8, missing `=`, or an invalid
    /// name/value). Unscreened cookie material may appear anywhere in the
    /// response metadata, so the declared Content-Type is withheld even
    /// when it echoes no known secret.
    metadata_unreviewed: bool,
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
/// unparsable body that was fully screened keeps byte-exact degraded evidence
/// (base64, sha256, Content-Type, reason and status) instead of an empty
/// schedule. A body whose decoded spellings cannot all be screened is
/// withheld rather than exported.
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
    let safe_content_type = if screening.metadata_echo || screening.metadata_unreviewed {
        None
    } else {
        content_type
    };
    let denied = !screening.echo && session_denied(bytes);
    let output = if screening.echo {
        withheld(status, safe_content_type, bytes, "credential_echo")
    } else if screening.body_unreviewed {
        withheld(
            status,
            safe_content_type,
            bytes,
            "response_safety_unreviewed",
        )
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
/// by student-context initialization and exactly one `loadXskbData.do` read. The session never persists, refreshes
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
    let mut initialization_observed: Option<(u16, Option<String>, bool)> = None;
    let prepared = cas::authenticate_service(&mut lease, &client, CasService::Gsmis, credentials)
        .and_then(|mut session| {
            let url = url::Url::parse(TIMETABLE_URL).map_err(|_| session_invalid())?;
            let page_url = url::Url::parse(TIMETABLE_PAGE_URL).map_err(|_| session_invalid())?;
            let init_url = url::Url::parse(TIMETABLE_INIT_URL).map_err(|_| session_invalid())?;
            let (page_cookie, page_expiry) = session.cookie_header_for_transmission(&page_url)?;
            let page_cookie = page_cookie.ok_or_else(|| {
                error(
                    "authentication_unconfirmed",
                    "the timetable application cookie is missing; no entry was sent",
                )
            })?;
            admit_session_read(&mut lease)?;
            if page_expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
                return Err(error(
                    "scoped_cookie_unusable",
                    "the timetable cookie expired before application entry; no request was sent",
                ));
            }
            let mut page = client
                .get(TIMETABLE_PAGE_URL)
                .header("Cookie", page_cookie)
                .header(
                    "Accept",
                    "text/html",
                )
                .header("Referer", TIMETABLE_PORTAL_URL)
                .timeout(std::time::Duration::from_secs(45))
                .header("Accept-Encoding", "identity")
                .build()
                .map_err(|_| session_invalid())?;
            if let Some(value) = page.headers_mut().get_mut("cookie") {
                value.set_sensitive(true);
            }
            let page = client.execute(page).map_err(|_| {
                error(
                    "network_error",
                    "timetable application entry failed; no initialization or read was sent",
                )
            })?;
            let page = receive_context_response(
                page,
                &mut lease,
                &mut session,
                &page_url,
                &mut initialization_observed,
            )?;
            screen_context_response(&page, &input, &session, false)?;
            if page.status == 429 || page.retry_after.is_some() {
                return Err(error(
                    "cooldown",
                    "timetable application entry was deferred",
                ));
            }
            if page.status != 200 {
                return Err(error(
                    "authentication_unconfirmed",
                    "timetable application entry was refused by GSMIS; no initialization was sent",
                ));
            }
            let page_mime = page
                .content_type
                .as_deref()
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            if !page_mime.is_some_and(|value| value.eq_ignore_ascii_case("text/html"))
                || page.body.iter().all(|byte| byte.is_ascii_whitespace())
            {
                return Err(error(
                    "authentication_unconfirmed",
                    "timetable application entry was not a nonempty HTML document; no initialization was sent",
                ));
            }

            let (cookie, init_expiry) = session.cookie_header_for_transmission(&init_url)?;
            let cookie = cookie.ok_or_else(|| {
                error(
                    "auth_latched",
                    "the timetable initialization cookie is missing; no initialization was sent",
                )
            })?;
            admit_session_read(&mut lease)?;
            if init_expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
                return Err(error(
                    "scoped_cookie_unusable",
                    "the timetable cookie expired before initialization; no initialization was sent",
                ));
            }
            let init = session_request(&client, TIMETABLE_INIT_URL, cookie)
                .form(&[("XH", "")])
                .timeout(std::time::Duration::from_secs(45))
                .header("Accept-Encoding", "identity")
                .build()
                .map_err(|_| session_invalid())?;
            let mut init = init;
            if let Some(value) = init.headers_mut().get_mut("cookie") {
                value.set_sensitive(true);
            }
            let init = client.execute(init).map_err(|_| {
                error(
                    "network_error",
                    "timetable context initialization failed; no read was sent",
                )
            })?;
            let init = receive_context_response(
                init,
                &mut lease,
                &mut session,
                &init_url,
                &mut initialization_observed,
            )?;
            screen_context_response(&init, &input, &session, true)?;
            if init.status == 429 || init.retry_after.is_some() {
                return Err(error("cooldown", "timetable initialization was deferred"));
            }
            if init.status != 200 {
                return Err(error("authentication_unconfirmed", "timetable context initialization was refused by GSMIS; inspect its HTTP status and safety receipt"));
            }
            if !student_context_present(&init.body)? {
                return Err(error("authentication_unconfirmed", "the current account has no student timetable context"));
            }
            let (cookie, expiry) = session.cookie_header_for_transmission(&url)?;
            let cookie = cookie.ok_or_else(|| {
                error("auth_latched", "the initialized timetable session has no usable cookie")
            })?;
            let builder = xskb_request(&client, cookie, &input.read.xnxqdm);
            let mut request = builder
                .timeout(std::time::Duration::from_secs(45))
                .header("Accept-Encoding", "identity")
                .build()
                .map_err(|_| session_invalid())?;
            if let Some(value) = request.headers_mut().get_mut("cookie") {
                value.set_sensitive(true);
            }
            admit_session_read(&mut lease)?;
            Ok((session, expiry, request))
        });
    let (session, cookie_expiry, request) = match prepared {
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
                _ if initialization_observed.is_some() => {
                    let (status, retry_after, challenge) = initialization_observed
                        .take()
                        .expect("initialized observation is present");
                    lease.finish(Outcome::Http {
                        status,
                        retry_after: retry_after.as_deref(),
                        challenge,
                        network_failure: false,
                    })
                }
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
    // GSMIS re-issues its session cookie on the read. Absorb the declarations
    // into the invocation-only jar so their values join the credential screen;
    // the read remains terminal and nothing is persisted or replayed.
    let issued = IssuedCookies::absorb(response.headers());
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
    let metadata_echo = content_type.as_deref().is_some_and(|value| {
        contains(value.as_bytes()) || issued.contains_secret_bytes(value.as_bytes())
    });
    let body_screening = decoded_body_screening(&bytes, &contains);
    // JSON-escaped spellings of an issued cookie value are screened with the
    // same decoded-literal pass the stdin credentials receive.
    let issued_screening = if issued.entries.is_empty() {
        BodyScreening::Clear
    } else {
        decoded_body_screening(&bytes, &|candidate: &[u8]| {
            issued.contains_secret_bytes(candidate)
        })
    };
    // The issued cookie values are session material too: a body or header
    // echoing one is withheld, and an incompletely screened declaration set
    // withholds the body rather than exporting it unscreened.
    let echo = contains(&bytes)
        || issued.contains_secret_bytes(&bytes)
        || metadata_echo
        || body_screening == BodyScreening::Echo
        || issued_screening == BodyScreening::Echo;
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
                header_challenge,
                metadata_echo,
                metadata_unreviewed: !issued.complete,
                echo,
                body_unreviewed: body_screening == BodyScreening::Unreviewable
                    || issued_screening == BodyScreening::Unreviewable
                    || !issued.complete,
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
                    "start_week": "1-based first week (1..=104)",
                    "end_week": "1-based last week in 1..=104 and >= start_week; occurrences past the semester end are dropped",
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
        "description": "One explicit in-memory CAS login to GSMIS, one wdkbapp application document, one initXsxx.do student-context initialization and exactly one loadXskbData.do read; no persistence, refresh, retry or writes. Session cookies issued by the application and read responses are absorbed into the invocation-only jar and screened as credential material, never persisted or replayed.",
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
        "context_read_url": TIMETABLE_INIT_URL,
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
    fn course_week_bounds_refuse_wrapping_and_keep_calendar_boundaries() {
        let mut input = json!({
            "semester":{"start_date":"2026-09-21","weeks":2},
            "courses":[{"name":"Synthetic","day":"monday","start_week":1,
                "end_week":2,"start_time":"08:00","end_time":"09:00"}]
        });
        let ordinary = run(&input.to_string());
        assert_eq!(ordinary["event_count"], 2);
        let ics = ordinary["ics"].as_str().unwrap();
        assert!(ics.contains("DTSTART:20260921T080000"));
        assert!(ics.contains("DTSTART:20260928T080000"));

        for field in ["start_week", "end_week"] {
            for week in [0, u64::from(MAX_WEEKS) + 1, 4_294_967_298, u64::MAX] {
                let mut invalid = input.clone();
                invalid["courses"][0][field] = json!(week);
                let refused = run(&invalid.to_string());
                assert_eq!(refused["error"], "invalid_input", "{field}={week}");
                assert!(refused.get("ics").is_none());
            }
        }
        input["semester"]["weeks"] = json!(MAX_WEEKS);
        input["courses"][0]["start_week"] = json!(MAX_WEEKS);
        input["courses"][0]["end_week"] = json!(MAX_WEEKS);
        let last = run(&input.to_string());
        assert_eq!(last["event_count"], 1);
        assert!(
            last["ics"]
                .as_str()
                .unwrap()
                .contains("DTSTART:20280911T080000")
        );
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

    #[test]
    fn student_context_requires_a_complete_bound_identity() {
        let valid =
            br#"{"data":[{"XH":"synthetic-student","YXDM":"1","YXDM_DISPLAY":"Synthetic"}]}"#;
        assert_eq!(student_context_present(valid), Ok(true));
        assert_eq!(student_context_present(br#"{"data":[]}"#), Ok(false));
        for invalid in [
            br#"{"data":[{"YXDM":"1"}]}"#.as_slice(),
            br#"{"data":[{"XH":""}]}"#,
            br#"{"data":[{"XH":"a","XH":"b"}]}"#,
            br#"{"data":[{"XH":7}]}"#,
            br#"{"data":[{"XH":"synthetic-student"}]} trailing"#,
            br#"[]"#,
        ] {
            assert_eq!(
                student_context_present(invalid).unwrap_err().code,
                "upstream_parse"
            );
        }
    }

    #[test]
    fn internal_student_context_allows_only_the_expected_identity_echo() {
        let input: SessionInput =
            serde_json::from_str(&session_input().to_string()).expect("synthetic session input");
        let mut session = cas::ServiceSession::test_session_with_cookies(
            CasService::Gsmis,
            TIMETABLE_PAGE_URL,
            &["GS_SESSIONID=synthetic-cookie; Path=/gsapp/"],
        );
        let page_url = url::Url::parse(TIMETABLE_PAGE_URL).unwrap();
        session
            .cookie_header_for_transmission(&page_url)
            .expect("the complete context header is retained");
        let mut rotation = reqwest::header::HeaderMap::new();
        rotation.append(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static(
                "GS_SESSIONID=synthetic-rotated; Path=/gsapp/",
            ),
        );
        session
            .absorb_gsmis_headers(&page_url, &rotation)
            .expect("the rotated cookie is admitted");
        let response = |body: String| ContextResponse {
            status: 200,
            retry_after: None,
            challenge: false,
            content_type: Some("application/json".into()),
            body: Zeroizing::new(body.into_bytes()),
        };
        let context =
            response(json!({"data":[{"XH":input.username.as_str(),"XM":"Synthetic"}]}).to_string());
        let first_secret_char = input.password.chars().next().unwrap();
        let escaped_secret = format!(
            "\\u{:04x}{}",
            first_secret_char as u32,
            &input.password[first_secret_char.len_utf8()..]
        );
        let escaped_secret_body =
            json!({"data":[{"XH":input.username.as_str()}],"echo":input.password.as_str()})
                .to_string()
                .replace(input.password.as_str(), &escaped_secret);
        assert_eq!(
            screen_context_response(&context, &input, &session, true),
            Ok(())
        );
        assert_eq!(
            screen_context_response(&context, &input, &session, false)
                .unwrap_err()
                .code,
            "credential_echo"
        );
        for body in [
            json!({"data":[{"XH":input.username.as_str()}],"echo":input.password.as_str()})
                .to_string(),
            json!({"data":[{"XH":input.username.as_str()}],"echo":"synthetic-cookie"}).to_string(),
            json!({"data":[{"XH":input.username.as_str()}],"echo":STANDARD.encode("GS_SESSIONID=synthetic-cookie")})
                .to_string(),
            escaped_secret_body,
        ] {
            assert_eq!(
                screen_context_response(&response(body), &input, &session, true)
                    .unwrap_err()
                    .code,
                "credential_echo"
            );
        }
    }

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

    /// Screen one body the way `session_with_network` does, then admit it.
    /// The `contains` predicate plays the role of the transmitted cookie,
    /// issued jar and stdin credentials in production.
    fn screened_admission(status: u16, content_type: Option<&str>, body: &[u8]) -> ReadAdmission {
        let contains = |candidate: &[u8]| crate::net::carries_secret(candidate, "secret-canary-9");
        let screening = decoded_body_screening(body, &contains);
        let assessment = complete_assessment(content_type, body);
        admit_read_body(
            status,
            content_type,
            body,
            "20261",
            assessment,
            ReadScreening {
                echo: contains(body) || screening == BodyScreening::Echo,
                body_unreviewed: screening == BodyScreening::Unreviewable,
                ..ReadScreening::default()
            },
        )
    }

    /// A decoded credential must be found wherever it sits: Unicode-escaped
    /// inside a member name or in a duplicate member a lenient tree parser
    /// would silently drop. Neither form may reach fallback export.
    #[test]
    fn decoded_echoes_in_names_and_duplicate_members_are_withheld() {
        let content_type = Some("application/json");
        // The credential's escaped spelling appears only in a member name;
        // a screen that visits values only misses it, and the raw bytes
        // never contain the decoded spelling.
        let escaped_name: &[u8] = br#"{"\u0073ecret-canary-9":0}"#;
        // The first duplicate member carries the escaped credential; a
        // lenient tree parser keeps only the second, ordinary occurrence.
        let duplicate: &[u8] = br#"{"x":"\u0073ecret-canary-9","x":"ordinary"}"#;
        for body in [escaped_name, duplicate] {
            assert!(serde_json::from_slice::<Value>(body).is_ok());
            assert_eq!(
                complete_assessment(content_type, body),
                crate::html::ChallengeAssessment::Clear
            );
            let admission = screened_admission(200, content_type, body);
            let output = &admission.output;
            assert_eq!(output["result"], "sensitive_response_withheld");
            assert_eq!(output["raw_evidence_withheld"], true);
            assert!(output.get("raw_response_base64").is_none());
            assert_eq!(output["body_byte_length"], body.len());
            assert_eq!(
                output["raw_response_sha256"],
                format!("{:x}", Sha256::digest(body))
            );
        }
    }

    /// A body part that cannot be screened — an escaped JSON literal the
    /// decoder rejects, whether by an invalid escape or a missing closing
    /// quote — is withheld rather than presumed safe.
    #[test]
    fn unscreenable_body_is_withheld() {
        let content_type = Some("application/json");
        for unscreenable in [
            // An invalid escape sequence: the literal exists but no decoder
            // can produce its spelling.
            br#"{"x":"abc\q"}"#.as_slice(),
            // An escaped literal cut off before its closing quote: a lenient
            // consumer may still recover a credential spelling from it.
            br#"{"x":"\u0041"#.as_slice(),
        ] {
            let admission = screened_admission(200, content_type, unscreenable);
            let output = &admission.output;
            assert_eq!(
                output["result"], "sensitive_response_withheld",
                "{unscreenable:?}"
            );
            assert_eq!(output["raw_evidence_withheld"], true);
            assert!(output.get("raw_response_base64").is_none());
        }
    }

    /// The module's synthetic session fixture with one term substituted.
    fn term_request(term: &str) -> String {
        let mut request = session_input();
        request["read"]["xnxqdm"] = json!(term);
        request.to_string()
    }

    fn headers_with(declarations: &[&str]) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        for declaration in declarations {
            headers.append(
                reqwest::header::SET_COOKIE,
                reqwest::header::HeaderValue::from_str(declaration)
                    .expect("fixture declaration must be a header value"),
            );
        }
        headers
    }

    /// A read response that re-issues the session cookie is no longer
    /// refused: the jar absorbs the declaration and a clean body parses.
    #[test]
    fn issued_session_cookie_is_absorbed_and_clean_body_parses() {
        let jar = IssuedCookies::absorb(&headers_with(&[
            "JSESSIONID=synthetic-issued-7f2; Path=/gsapp; HttpOnly",
            "route=synthetic-route-a; Path=/; Secure",
        ]));
        assert!(jar.complete);
        assert_eq!(jar.entries.len(), 2);
        assert!(jar.contains_secret_bytes(b"JSESSIONID=synthetic-issued-7f2"));
        // A cookie attribute (Path, HttpOnly) is not a credential carrier.
        assert!(!jar.contains_secret_bytes(b"/gsapp"));

        let body = timetable_body().to_string();
        let content_type = Some("application/json");
        let admission = admit_read_body(
            200,
            content_type,
            body.as_bytes(),
            "20261",
            complete_assessment(content_type, body.as_bytes()),
            ReadScreening::default(),
        );
        assert!(!admission.denied);
        assert_eq!(admission.output["result"], "parsed");
    }

    /// Issued cookie values are session material: a body echoing one, even
    /// behind a JSON escape, is withheld rather than exported.
    #[test]
    fn issued_cookie_echo_is_withheld_including_escaped_spellings() {
        let jar = IssuedCookies::absorb(&headers_with(&[
            "JSESSIONID=synthetic-issued-7f2; Path=/gsapp; HttpOnly",
        ]));
        assert!(jar.complete);
        assert!(jar.contains_secret_bytes(br#"{"session":"synthetic-issued-7f2"}"#));
        // The decoded spelling of an escaped literal carries the value too.
        let escaped = br#"{"session":"synthetic-issued-\u0037f2"}"#;
        assert!(!jar.contains_secret_bytes(escaped));
        let screening = decoded_body_screening(escaped, &|candidate: &[u8]| {
            jar.contains_secret_bytes(candidate)
        });
        assert_eq!(screening, BodyScreening::Echo);
        // An unquoted cookie value is screened in both spellings.
        let quoted = IssuedCookies::absorb(&headers_with(&[
            "JSESSIONID=\"quoted-issued-91c\"; Path=/gsapp",
        ]));
        assert!(quoted.contains_secret_bytes(b"quoted-issued-91c"));
        assert!(quoted.contains_secret_bytes(b"\"quoted-issued-91c\""));
    }

    /// Declarations that cannot be fully screened leave the jar incomplete,
    /// which withholds the body instead of exporting it unscreened.
    #[test]
    fn unreviewable_cookie_declarations_withhold_the_body() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_bytes(b"JSESSIONID=ok; Path=/")
                .expect("valid declaration"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_bytes(b"JSESSIONID=\xff\xfe; Path=/")
                .expect("non-UTF-8 header values are representable"),
        );
        let jar = IssuedCookies::absorb(&headers);
        assert!(!jar.complete);
        // The valid declaration is still retained for screening.
        assert_eq!(jar.entries.len(), 1);

        let body = timetable_body().to_string();
        let content_type = Some("application/json");
        let admission = admit_read_body(
            200,
            content_type,
            body.as_bytes(),
            "20261",
            complete_assessment(content_type, body.as_bytes()),
            ReadScreening {
                body_unreviewed: !jar.complete,
                ..ReadScreening::default()
            },
        );
        assert_eq!(admission.output["result"], "sensitive_response_withheld");
        assert_eq!(
            admission.output["fallback_reason"],
            "response_safety_unreviewed"
        );
        assert!(admission.output.get("raw_response_base64").is_none());
    }

    /// An over-limit declaration set is refused as unreviewable, not
    /// truncated into a partially screened jar.
    #[test]
    fn excessive_cookie_declarations_are_unreviewable() {
        let declarations = vec!["route=synthetic-route-a; Path=/"; MAX_ISSUED_COOKIES + 1];
        let jar = IssuedCookies::absorb(&headers_with(&declarations));
        assert!(!jar.complete);
        assert!(jar.entries.is_empty());
    }

    /// Admit one body the way `session_with_network` does once the issued
    /// jar is known: metadata is unreviewed whenever the jar is incomplete,
    /// and any body echo of an issued value is refused. The output
    /// assertions below are consumer-level, not just jar-level.
    fn issued_admission(
        jar: &IssuedCookies,
        content_type: Option<&str>,
        body: &[u8],
    ) -> ReadAdmission {
        let issued_screening = if jar.entries.is_empty() {
            BodyScreening::Clear
        } else {
            decoded_body_screening(body, &|candidate: &[u8]| {
                jar.contains_secret_bytes(candidate)
            })
        };
        let assessment = complete_assessment(content_type, body);
        admit_read_body(
            200,
            content_type,
            body,
            "20261",
            assessment,
            ReadScreening {
                echo: jar.contains_secret_bytes(body) || issued_screening == BodyScreening::Echo,
                metadata_unreviewed: !jar.complete,
                body_unreviewed: issued_screening == BodyScreening::Unreviewable || !jar.complete,
                ..ReadScreening::default()
            },
        )
    }

    /// An over-limit jar cannot screen the Content-Type for the cookie
    /// values it dropped. A MIME essence echoing one of those values must
    /// not survive as "safe" metadata, and the body is withheld too.
    #[test]
    fn over_limit_declarations_withhold_metadata_echoing_unscreened_cookie() {
        let mut declarations = vec!["route=synthetic-route-a; Path=/"; MAX_ISSUED_COOKIES];
        declarations.push("JSESSIONID=private-issued-7f2; Path=/gsapp; HttpOnly");
        let jar = IssuedCookies::absorb(&headers_with(&declarations));
        assert!(!jar.complete);
        assert!(jar.entries.is_empty());

        let body = timetable_body().to_string();
        let content_type = Some("application/private-issued-7f2");
        // Even though no known value is echoed, the unreviewed declaration
        // set means no metadata spelling can be certified safe.
        let admission = issued_admission(&jar, content_type, body.as_bytes());
        let output = &admission.output;
        assert_eq!(output["result"], "sensitive_response_withheld");
        assert_eq!(output["fallback_reason"], "response_safety_unreviewed");
        assert_eq!(output["content_type"], Value::Null);
        assert_eq!(output["content_type_parameters_withheld"], false);
        assert!(output.get("raw_response_base64").is_none());
        assert!(output.get("schedule_row_count").is_none());
    }

    /// Every declaration that cannot be fully reviewed — no `=`, or an
    /// invalid name/value — leaves the jar incomplete so both the body and
    /// the Content-Type metadata are withheld, rather than skipping the
    /// declaration and exporting the rest as screened.
    #[test]
    fn invalid_or_ambiguous_declarations_withhold_body_and_metadata() {
        let content_type = Some("application/json; charset=utf-8");
        let body = timetable_body().to_string();
        for declaration in [
            // No `=` at all: the value boundary is ambiguous.
            "JSESSIONID",
            // An invalid name (spaces are not a cookie-name token).
            "bad name=value; Path=/",
            // An invalid value (a raw space is outside the cookie octets).
            "JSESSIONID=bad value; Path=/",
            // An unterminated quoted value is not a valid cookie value.
            "JSESSIONID=\"unterminated; Path=/",
        ] {
            let jar = IssuedCookies::absorb(&headers_with(&[declaration]));
            assert!(!jar.complete, "{declaration} was treated as screened");
            let admission = issued_admission(&jar, content_type, body.as_bytes());
            let output = &admission.output;
            assert_eq!(
                output["result"], "sensitive_response_withheld",
                "{declaration} leaked a body"
            );
            assert_eq!(output["fallback_reason"], "response_safety_unreviewed");
            assert_eq!(output["content_type"], Value::Null, "{declaration}");
            assert!(output.get("raw_response_base64").is_none());
            assert!(output.get("schedule_row_count").is_none());
        }
    }

    /// A clean, valid declaration set stays readable: the jar is complete,
    /// the Content-Type is retained, and a body with no echo parses. Valid
    /// empty values (cookie deletion) are absorbed, not treated as invalid,
    /// and a quoted empty value never matches an arbitrary empty string.
    #[test]
    fn clean_valid_declarations_keep_body_and_metadata_readable() {
        let jar = IssuedCookies::absorb(&headers_with(&[
            "JSESSIONID=synthetic-issued-7f2; Path=/gsapp; HttpOnly",
            // Deleting a cookie: a valid empty value, not a screening gap.
            "route=; Path=/; Max-Age=0",
            // A quoted empty value is likewise valid and carries no secret.
            "legacy=\"\"; Path=/",
        ]));
        assert!(jar.complete);
        assert_eq!(jar.entries.len(), 1);
        // The empty deletions never match arbitrary content, quoted or not.
        assert!(!jar.contains_secret_bytes(b"\"any\""));
        assert!(!jar.contains_secret_bytes(b"ordinary text"));

        let body = timetable_body().to_string();
        let content_type = Some("application/json");
        let admission = issued_admission(&jar, content_type, body.as_bytes());
        assert_eq!(admission.output["result"], "parsed");
        // A clean body parses into real schedule output rather than being
        // withheld, and no credential echo was raised.
        assert_eq!(admission.output["schedule_row_count"], 1);
        assert!(admission.output.get("raw_evidence_withheld").is_none());
    }

    /// Raw and JSON-escaped echoes of an issued value are still refused
    /// even though the declaration set is complete and reviewable.
    #[test]
    fn complete_jar_still_withholds_raw_and_escaped_echoes() {
        let jar = IssuedCookies::absorb(&headers_with(&[
            "JSESSIONID=synthetic-issued-7f2; Path=/gsapp; HttpOnly",
        ]));
        assert!(jar.complete);
        let content_type = Some("application/json");
        for body in [
            br#"{"session":"synthetic-issued-7f2"}"#.as_slice(),
            br#"{"session":"synthetic-issued-\u0037f2"}"#.as_slice(),
        ] {
            let admission = issued_admission(&jar, content_type, body);
            let output = &admission.output;
            assert_eq!(output["result"], "sensitive_response_withheld");
            assert_eq!(output["fallback_reason"], "credential_echo");
            assert!(output.get("raw_response_base64").is_none());
        }
    }

    /// A complete `name=value` pair has different base64 boundaries from
    /// the value alone. A body echoing only the encoded full pair must be
    /// refused even though neither the literal value nor base64(value)
    /// appears anywhere in it. Ordinary content stays readable.
    #[test]
    fn complete_cookie_pair_base64_and_urlsafe_echoes_are_refused() {
        let content_type = Some("application/json");
        // Standard base64 of the complete pair.
        let jar = IssuedCookies::absorb(&headers_with(&["sid=abc; Path=/; HttpOnly"]));
        assert!(jar.complete);
        assert_eq!(jar.entries.len(), 1);
        let pair = "sid=abc";
        // Sanity: the bare value alone does not match the encoded pair.
        let pair_b64 = STANDARD.encode(pair);
        assert!(!net::carries_secret(pair_b64.as_bytes(), "abc"));
        assert!(net::carries_secret(pair_b64.as_bytes(), pair));
        assert!(jar.contains_secret_bytes(pair_b64.as_bytes()));
        let encoded = STANDARD.encode(pair);
        let body = format!(r#"{{"session":"{encoded}"}}"#);
        let admission = issued_admission(&jar, content_type, body.as_bytes());
        assert_eq!(admission.output["result"], "sensitive_response_withheld");
        assert_eq!(admission.output["fallback_reason"], "credential_echo");
        assert!(admission.output.get("raw_response_base64").is_none());
        // The full-pair echo in a Content-Type is refused as metadata echo.
        let admission = issued_admission(&jar, Some(encoded.as_str()), body.as_bytes());
        assert_eq!(admission.output["result"], "sensitive_response_withheld");
        // Ordinary content with this jar is still readable.
        let body = timetable_body().to_string();
        let admission = issued_admission(&jar, content_type, body.as_bytes());
        assert_eq!(admission.output["result"], "parsed");
        assert_eq!(admission.output["schedule_row_count"], 1);

        // URL-safe base64 of a complete pair whose standard encoding
        // carries '+' or '/': the two alphabets differ, and only the pair
        // screen (not the bare value) covers this boundary.
        let jar = IssuedCookies::absorb(&headers_with(&["sid=a?b; Path=/; HttpOnly"]));
        assert!(jar.complete);
        let pair = "sid=a?b";
        let standard = STANDARD.encode(pair);
        let url_encoded = base64::engine::general_purpose::URL_SAFE.encode(pair);
        assert!(
            standard.contains('+') || standard.contains('/'),
            "fixture must exercise the URL-safe alphabet: {standard}"
        );
        assert!(jar.contains_secret_bytes(url_encoded.as_bytes()));
        let body = format!(r#"{{"session":"{url_encoded}"}}"#);
        let admission = issued_admission(&jar, content_type, body.as_bytes());
        assert_eq!(admission.output["result"], "sensitive_response_withheld");
        assert_eq!(admission.output["fallback_reason"], "credential_echo");
        assert!(admission.output.get("raw_response_base64").is_none());
    }

    /// A value just over the 4096-byte review bound cannot be screened at
    /// all. It must leave the jar incomplete and withhold both the body and
    /// the Content-Type, rather than silently dropping the declaration and
    /// exporting the rest as screened.
    #[test]
    fn over_long_cookie_value_is_unreviewable_and_withholds_output() {
        let long_value = "a".repeat(4097);
        let declaration = format!("JSESSIONID={long_value}; Path=/gsapp");
        let jar = IssuedCookies::absorb(&headers_with(&[declaration.as_str()]));
        assert!(!jar.complete, "4097-byte value was treated as screened");
        assert!(jar.entries.is_empty());
        assert!(jar.entries.is_empty());

        let body = timetable_body().to_string();
        let admission = issued_admission(&jar, Some("application/json"), body.as_bytes());
        let output = &admission.output;
        assert_eq!(output["result"], "sensitive_response_withheld");
        assert_eq!(output["fallback_reason"], "response_safety_unreviewed");
        assert_eq!(output["content_type"], Value::Null);
        assert!(output.get("raw_response_base64").is_none());

        // Exactly at the bound is still reviewable and stays readable.
        let ok_value = "a".repeat(4096);
        let declaration = format!("JSESSIONID={ok_value}; Path=/gsapp");
        let jar = IssuedCookies::absorb(&headers_with(&[declaration.as_str()]));
        assert!(jar.complete);
        assert_eq!(jar.entries.len(), 1);
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

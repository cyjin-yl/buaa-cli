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

use serde_json::{Value, json};

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
    for (ci, course) in courses.iter().enumerate() {
        for occ in occurrences(start_date, weeks, course) {
            let uid = format!(
                "buaa-cli/timetable/{semester_start_iso}/{ci}/{}",
                occ.date_z
            );
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

/// Describe the command's input/output contract for `buaa schema`.
pub fn schema() -> Value {
    json!({
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
    })
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

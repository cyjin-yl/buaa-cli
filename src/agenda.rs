//! Local school and personal agenda.
//!
//! Views, filters, Beijing-time recurrence, local completion notes, conflict
//! warnings, and calendar export follow BUAASubnet/UBAA
//! `docs/site/features/agenda.md` at `3ac2ebd6c30162cd1ce1fc50964caa25ed22092f`
//! (MIT, © 2026 MooreFoss). This is original code. School overlays stay in the
//! supplied document and are not campus writes. Cloud-drive sync is refused
//! because that UBAA path is not a verified CLI contract.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::civil_time::{
    at_clock, beijing_days, clock_seconds, format_beijing, format_date, format_utc, parse_beijing,
    parse_date, weekday,
};
use crate::{
    governor::{FollowupError, Governor, Outcome, RequestKind, RequestLease},
    net::{self, Error},
    recordings::session::{self as cas, CasService, SsoCredentials},
    timetable::{self, admit_session_read, receive_context_response, screen_context_response},
};

const AGENDA_PORTAL_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do";
const AGENDA_QUERY_URL: &str =
    "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/queryRcap.do";

const CREDIT: &str =
    "BUAASubnet/UBAA@3ac2ebd6c30162cd1ce1fc50964caa25ed22092f (MIT, © 2026 MooreFoss)";
const MAX_ITEMS: usize = 256;
const MAX_OCCURRENCES: usize = 400;
const MAX_RANGE: i64 = 400 * 86_400;
const SOURCES: [&str; 7] = [
    "course",
    "assignment",
    "boya",
    "exam",
    "seminar",
    "checkin",
    "sunlight",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    now: String,
    operation: String,
    school: Vec<School>,
    personal: Vec<Personal>,
    range_start: Option<String>,
    range_end: Option<String>,
    view: Option<String>,
    sources: Option<Vec<String>>,
    #[serde(default)]
    todo_only: bool,
    #[serde(default)]
    show_completed: bool,
    #[serde(default)]
    show_hidden: bool,
    query: Option<String>,
    item: Option<Personal>,
    #[serde(default)]
    save_despite_conflict: bool,
    target_id: Option<String>,
    occurrence: Option<String>,
    scope: Option<String>,
    completed: Option<bool>,
    hidden: Option<bool>,
    note: Option<String>,
    #[serde(default)]
    include_completed: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct School {
    id: String,
    source: String,
    title: String,
    location: Option<String>,
    note: Option<String>,
    start: Option<String>,
    end: Option<String>,
    due: Option<String>,
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    hidden: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Personal {
    id: String,
    kind: String,
    title: String,
    location: Option<String>,
    note: Option<String>,
    color: Option<String>,
    start: Option<String>,
    end: Option<String>,
    due: Option<String>,
    #[serde(default)]
    all_day: bool,
    #[serde(default)]
    undated: bool,
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    recurrence: Recurrence,
    #[serde(default)]
    exdates: Vec<String>,
    until: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Recurrence {
    #[serde(default = "none_kind")]
    kind: String,
    interval: Option<u32>,
    #[serde(default)]
    weekdays: Vec<u32>,
    first_monday: Option<String>,
    start_week: Option<u32>,
    end_week: Option<u32>,
    parity: Option<String>,
    weekday: Option<u32>,
    #[serde(default)]
    skip_dates: Vec<String>,
}

impl Default for Recurrence {
    fn default() -> Self {
        Self {
            kind: none_kind(),
            interval: None,
            weekdays: Vec::new(),
            first_monday: None,
            start_week: None,
            end_week: None,
            parity: None,
            weekday: None,
            skip_dates: Vec::new(),
        }
    }
}

fn none_kind() -> String {
    "none".to_owned()
}

struct Occurrence {
    id: String,
    source: String,
    kind: String,
    title: String,
    location: Option<String>,
    note: Option<String>,
    start: i64,
    end: Option<i64>,
    all_day: bool,
    completed: bool,
    hidden: bool,
}

pub fn run(input: &str) -> Value {
    let parsed = match serde_json::from_str::<Input>(input) {
        Ok(value) => value,
        Err(_) => return invalid("input must be one agenda JSON object"),
    };
    match dispatch(parsed) {
        Ok(value) => value,
        Err(message) => invalid(message),
    }
}

fn dispatch(mut input: Input) -> Result<Value, &'static str> {
    let now = parse_beijing(&input.now).ok_or("now must be a Beijing timestamp")?;
    validate_collection(&mut input.school, &mut input.personal)?;
    match input.operation.as_str() {
        "project" | "export" => project_or_export(&input, now),
        "upcoming" => upcoming(&input, now),
        "add" => add(&mut input),
        "update" => update(&mut input),
        "delete" => delete(&mut input),
        "overlay" => overlay(&mut input),
        "sync" => Ok(base(
            &input,
            json!({
                "result": "blocked",
                "reason": "cloud_sync_unverified",
                "document_changed": false
            }),
        )),
        _ => Err("unknown agenda operation"),
    }
}

fn validate_collection(
    school: &mut [School],
    personal: &mut [Personal],
) -> Result<(), &'static str> {
    if school.len() > MAX_ITEMS || personal.len() > MAX_ITEMS {
        return Err("too many agenda items");
    }
    let mut ids = BTreeSet::new();
    for item in school.iter() {
        validate_id(&item.id)?;
        validate_text(&item.title, false)?;
        validate_optional(&item.location, 200)?;
        validate_optional(&item.note, 2000)?;
        if !SOURCES.contains(&item.source.as_str()) {
            return Err("unknown school source");
        }
        let start = parse_optional(item.start.as_deref(), "start")?;
        let end = parse_optional(item.end.as_deref(), "end")?;
        let due = parse_optional(item.due.as_deref(), "due")?;
        if item.source == "course" {
            match (start, end, due) {
                (Some(start), Some(end), None) if end > start => {}
                _ => return Err("a course needs a positive Beijing interval and no due time"),
            }
        } else if start.is_none() && end.is_none() && due.is_none() {
            return Err("a school item needs a start, end, or due time");
        }
        if !ids.insert(item.id.clone()) {
            return Err("agenda ids must be unique");
        }
    }
    for item in personal {
        validate_personal(item)?;
        if !ids.insert(item.id.clone()) {
            return Err("agenda ids must be unique");
        }
    }
    Ok(())
}

fn validate_personal(item: &Personal) -> Result<(), &'static str> {
    validate_id(&item.id)?;
    validate_text(&item.title, false)?;
    validate_optional(&item.location, 200)?;
    validate_optional(&item.note, 2000)?;
    if let Some(color) = item.color.as_deref() {
        let bytes = color.as_bytes();
        if bytes.len() != 7 || bytes[0] != b'#' || !bytes[1..].iter().all(u8::is_ascii_hexdigit) {
            return Err("color must be a #RRGGBB value");
        }
    }
    let start = parse_optional(item.start.as_deref(), "start")?;
    let end = parse_optional(item.end.as_deref(), "end")?;
    let due = parse_optional(item.due.as_deref(), "due")?;
    match item.kind.as_str() {
        "event" => {
            if item.undated || due.is_some() {
                return Err("an event cannot be undated or have a due time");
            }
            match (start, end) {
                (Some(start), Some(end)) if end > start => {}
                _ => return Err("an event needs a positive Beijing interval"),
            }
            if item.all_day
                && (clock_seconds(start.unwrap()) != 0 || clock_seconds(end.unwrap()) != 0)
            {
                return Err("an all-day event must start and end at Beijing midnight");
            }
        }
        "todo" => {
            if item.all_day {
                return Err("a todo cannot be all-day");
            }
            if item.undated {
                if start.is_some()
                    || end.is_some()
                    || due.is_some()
                    || item.recurrence.kind != "none"
                {
                    return Err("an undated todo has no time and does not repeat");
                }
            } else if start.is_some() || end.is_some() || due.is_none() {
                return Err("a dated todo has only a due time");
            }
        }
        _ => return Err("kind must be event or todo"),
    }
    validate_recurrence(item, start.or(due).unwrap_or(0))?;
    for date in item.exdates.iter().chain(item.recurrence.skip_dates.iter()) {
        if parse_date(date).is_none() {
            return Err("skip and exception dates must be civil dates");
        }
    }
    Ok(())
}

fn validate_recurrence(item: &Personal, origin: i64) -> Result<(), &'static str> {
    let recurrence = &item.recurrence;
    let interval = recurrence.interval;
    let teaching = recurrence.first_monday.is_some()
        || recurrence.start_week.is_some()
        || recurrence.end_week.is_some()
        || recurrence.parity.is_some()
        || recurrence.weekday.is_some();
    match recurrence.kind.as_str() {
        "none" => {
            if interval.is_some() || !recurrence.weekdays.is_empty() || teaching {
                return Err("a non-repeating item cannot carry recurrence fields");
            }
        }
        "daily" => {
            require_interval(interval, 1, 366)?;
            if !recurrence.weekdays.is_empty() || teaching {
                return Err("daily recurrence has only an interval");
            }
        }
        "weekly" => {
            require_interval(interval.or(Some(1)), 1, 52)?;
            validate_weekdays(&recurrence.weekdays)?;
            if teaching {
                return Err("weekly recurrence does not use teaching-week fields");
            }
        }
        "weekdays" => {
            if interval.is_some_and(|interval| interval != 1)
                || !recurrence.weekdays.is_empty()
                || teaching
            {
                return Err("weekday recurrence is every Monday through Friday");
            }
        }
        "teaching_week" => {
            if interval.is_some() || !recurrence.weekdays.is_empty() {
                return Err("teaching-week recurrence does not use interval or weekday lists");
            }
            let first = parse_date(recurrence.first_monday.as_deref().unwrap_or(""))
                .ok_or("teaching-week recurrence needs the Monday of week one")?;
            if weekday(first) != 0 {
                return Err("the first teaching week must start on a Monday");
            }
            match (
                recurrence.start_week,
                recurrence.end_week,
                recurrence.weekday,
            ) {
                (Some(start), Some(end), Some(day))
                    if (1..=104).contains(&start) && (start..=104).contains(&end) && day <= 6 => {}
                _ => return Err("teaching weeks must be ordered and inside 1 to 104"),
            }
            match recurrence.parity.as_deref().unwrap_or("all") {
                "all" | "odd" | "even" => {}
                _ => return Err("teaching-week parity must be all, odd, or even"),
            }
        }
        "custom" => {
            if teaching {
                return Err("custom recurrence does not use teaching-week fields");
            }
            if recurrence.weekdays.is_empty() {
                require_interval(interval, 1, 366)?;
            } else {
                require_interval(interval.or(Some(1)), 1, 52)?;
                validate_weekdays(&recurrence.weekdays)?;
            }
        }
        _ => return Err("unknown recurrence"),
    }
    if let Some(until) = item.until.as_deref() {
        let until = parse_beijing(until).ok_or("until must be a Beijing timestamp")?;
        if until <= origin {
            return Err("until must be after the first occurrence");
        }
    }
    if item.kind == "todo" && item.recurrence.kind != "none" && item.undated {
        return Err("a repeating todo needs a due time");
    }
    Ok(())
}

fn require_interval(interval: Option<u32>, low: u32, high: u32) -> Result<u32, &'static str> {
    match interval {
        Some(interval) if (low..=high).contains(&interval) => Ok(interval),
        _ => Err("recurrence interval is outside its allowed range"),
    }
}

fn validate_weekdays(days: &[u32]) -> Result<(), &'static str> {
    let mut seen = BTreeSet::new();
    if days.is_empty() || days.len() > 7 || days.iter().any(|day| *day > 6 || !seen.insert(*day)) {
        return Err("weekdays must be unique values from Monday 0 through Sunday 6");
    }
    Ok(())
}

fn project_or_export(input: &Input, now: i64) -> Result<Value, &'static str> {
    let (from, to, view) = required_range(input)?;
    let show_completed =
        input.show_completed || (input.operation == "export" && input.include_completed);
    let (occurrences, truncated, omitted_undated) =
        occurrences(input, from, to, show_completed, input.show_hidden)?;
    if input.operation == "project" {
        return Ok(base(
            input,
            json!({
                "result": "projected",
                "document_changed": false,
                "view": view,
                "truncated": truncated,
                "occurrences": occurrences.iter().map(occurrence_json).collect::<Vec<_>>()
            }),
        ));
    }
    let ics = render_ics(&occurrences, now)?;
    Ok(base(
        input,
        json!({
            "result": "exported",
            "document_changed": false,
            "snapshot": true,
            "auto_update": false,
            "truncated": truncated,
            "omitted_undated": omitted_undated,
            "exported": occurrences.len(),
            "ics": ics
        }),
    ))
}

fn upcoming(input: &Input, now: i64) -> Result<Value, &'static str> {
    let (mut occurrences, truncated, _) =
        occurrences(input, now, now + 8 * 86_400, false, input.show_hidden)?;
    for item in &input.personal {
        if item.undated
            && item.kind == "todo"
            && !item.completed
            && (input.show_hidden || !item.hidden)
        {
            occurrences.push(Occurrence {
                id: item.id.clone(),
                source: "personal".to_owned(),
                kind: "todo".to_owned(),
                title: item.title.clone(),
                location: item.location.clone(),
                note: item.note.clone(),
                start: now,
                end: None,
                all_day: false,
                completed: false,
                hidden: false,
            });
        }
    }
    occurrences.sort_by(|left, right| {
        (left.start, left.end, left.title.as_str(), left.id.as_str()).cmp(&(
            right.start,
            right.end,
            right.title.as_str(),
            right.id.as_str(),
        ))
    });
    Ok(base(
        input,
        json!({
            "result": "upcoming",
            "window_days": 8,
            "truncated": truncated,
            "occurrences": occurrences.iter().map(occurrence_json).collect::<Vec<_>>()
        }),
    ))
}

fn occurrences(
    input: &Input,
    from: i64,
    to: i64,
    show_completed: bool,
    include_hidden: bool,
) -> Result<(Vec<Occurrence>, bool, usize), &'static str> {
    let mut occurrences = Vec::new();
    let mut truncated = false;
    let mut omitted_undated = 0;
    for item in &input.school {
        let mut produced = false;
        for (start, end) in school_times(item)? {
            produced = true;
            if let Some(found) = accept(
                input,
                &item.id,
                &item.source,
                if item.source == "course" {
                    "event"
                } else {
                    "todo"
                },
                &item.title,
                item.location.as_deref(),
                item.note.as_deref(),
                start,
                end,
                false,
                item.completed,
                item.hidden,
                from,
                to,
                show_completed,
                include_hidden,
            ) {
                occurrences.push(found);
            }
        }
        if !produced {
            omitted_undated += 1;
        }
    }
    for item in &input.personal {
        if item.undated {
            omitted_undated += 1;
            continue;
        }
        let (hits, item_truncated) = expand(item, from, to)?;
        truncated |= item_truncated;
        for hit in hits {
            if let Some(found) = accept(
                input,
                &item.id,
                "personal",
                &item.kind,
                &item.title,
                item.location.as_deref(),
                item.note.as_deref(),
                hit.0,
                hit.1,
                item.all_day,
                item.completed,
                item.hidden,
                from,
                to,
                show_completed,
                include_hidden,
            ) {
                occurrences.push(found);
            }
        }
    }
    occurrences.sort_by(|left, right| {
        (left.start, left.title.as_str(), left.id.as_str()).cmp(&(
            right.start,
            right.title.as_str(),
            right.id.as_str(),
        ))
    });
    Ok((occurrences, truncated, omitted_undated))
}

fn accept(
    input: &Input,
    id: &str,
    source: &str,
    kind: &str,
    title: &str,
    location: Option<&str>,
    note: Option<&str>,
    start: i64,
    end: Option<i64>,
    all_day: bool,
    completed: bool,
    hidden: bool,
    from: i64,
    to: i64,
    show_completed: bool,
    include_hidden: bool,
) -> Option<Occurrence> {
    let inside = match end {
        Some(end) => start < to && end > from,
        None => (from..to).contains(&start),
    };
    if !inside || (hidden && !include_hidden) || (completed && !show_completed) {
        return None;
    }
    if input.todo_only && !(kind == "todo" || (source != "course" && source != "personal")) {
        return None;
    }
    if let Some(sources) = &input.sources
        && !sources.iter().any(|allowed| allowed == source)
    {
        return None;
    }
    if let Some(query) = &input.query
        && !title.contains(query)
        && !location.is_some_and(|value| value.contains(query))
        && !note.is_some_and(|value| value.contains(query))
    {
        return None;
    }
    Some(Occurrence {
        id: id.to_owned(),
        source: source.to_owned(),
        kind: kind.to_owned(),
        title: title.to_owned(),
        location: location.map(str::to_owned),
        note: note.map(str::to_owned),
        start,
        end,
        all_day,
        completed,
        hidden,
    })
}

fn school_times(item: &School) -> Result<Vec<(i64, Option<i64>)>, &'static str> {
    let start = parse_optional(item.start.as_deref(), "start")?;
    let end = parse_optional(item.end.as_deref(), "end")?;
    let due = parse_optional(item.due.as_deref(), "due")?;
    let mut times = Vec::new();
    if let (Some(start), Some(end)) = (start, end) {
        times.push((start, Some(end)));
    }
    if let Some(due) = due {
        times.push((due, None));
    }
    Ok(times)
}

fn expand(
    item: &Personal,
    from: i64,
    to: i64,
) -> Result<(Vec<(i64, Option<i64>)>, bool), &'static str> {
    let start = parse_optional(item.start.as_deref(), "start")?;
    let end = parse_optional(item.end.as_deref(), "end")?;
    let due = parse_optional(item.due.as_deref(), "due")?;
    let (origin, point_end) = if item.kind == "event" {
        (start.unwrap(), Some(end.unwrap()))
    } else {
        (due.unwrap(), None)
    };
    let duration = point_end.map(|end| end - origin).unwrap_or(0);
    let until = match item.until.as_deref() {
        None => None,
        Some(value) => Some(parse_beijing(value).ok_or("until must be a Beijing timestamp")?),
    };
    let mut skips = BTreeSet::new();
    for date in item.exdates.iter().chain(item.recurrence.skip_dates.iter()) {
        skips.insert(parse_date(date).ok_or("skip and exception dates must be civil dates")?);
    }
    let mut out = Vec::new();
    let mut truncated = false;
    let mut push = |date: i64, truncated: &mut bool| {
        if skips.contains(&date) {
            return;
        }
        let start = at_clock(date, clock_seconds(origin));
        if until.is_some_and(|until| start >= until) {
            return;
        }
        let end = point_end.map(|_| start + duration);
        let inside = match end {
            Some(end) => start < to && end > from,
            None => (from..to).contains(&start),
        };
        if !inside {
            return;
        }
        if out.len() == MAX_OCCURRENCES {
            *truncated = true;
            return;
        }
        out.push((start, end));
    };
    match item.recurrence.kind.as_str() {
        "none" => push(beijing_days(origin), &mut truncated),
        "daily" | "custom" if item.recurrence.weekdays.is_empty() => {
            let step = i64::from(item.recurrence.interval.unwrap_or(1)) * 86_400;
            let earliest = if point_end.is_none() {
                from
            } else {
                from - duration + 1
            };
            let mut index = if origin >= earliest {
                0
            } else {
                ceil_div(earliest - origin, step)
            };
            while index < 100_000 {
                let start = origin + index * step;
                if start >= to || until.is_some_and(|until| start >= until) {
                    break;
                }
                push(beijing_days(start), &mut truncated);
                if truncated {
                    break;
                }
                index += 1;
            }
            if index >= 100_000 {
                truncated = true;
            }
        }
        "weekly" | "weekdays" | "custom" | "teaching_week" => {
            let dates = candidate_dates(item, origin, from, to)?;
            for date in dates {
                push(date, &mut truncated);
                if truncated {
                    break;
                }
            }
        }
        _ => return Err("unknown recurrence"),
    }
    Ok((out, truncated))
}

fn candidate_dates(
    item: &Personal,
    origin: i64,
    _from: i64,
    to: i64,
) -> Result<Vec<i64>, &'static str> {
    let mut dates = Vec::new();
    let first_date = beijing_days(origin);
    let last = beijing_days(to) + 1;
    if item.recurrence.kind == "teaching_week" {
        let first = parse_date(item.recurrence.first_monday.as_deref().unwrap()).unwrap();
        let start_week = item.recurrence.start_week.unwrap();
        let end_week = item.recurrence.end_week.unwrap();
        let day = i64::from(item.recurrence.weekday.unwrap());
        let parity = item.recurrence.parity.as_deref().unwrap_or("all");
        for week in start_week..=end_week {
            let keep = match parity {
                "odd" => week % 2 == 1,
                "even" => week % 2 == 0,
                _ => true,
            };
            if keep {
                dates.push(first + i64::from(week - 1) * 7 + day);
            }
        }
        return Ok(dates);
    }
    let interval = i64::from(item.recurrence.interval.unwrap_or(1));
    let weekdays = if item.recurrence.kind == "weekdays" {
        vec![0, 1, 2, 3, 4]
    } else if item.recurrence.weekdays.is_empty() {
        vec![weekday(first_date)]
    } else {
        item.recurrence.weekdays.clone()
    };
    let anchor = first_date - i64::from(weekday(first_date));
    let mut week = 0;
    while week < 10_000 {
        let monday = anchor + week * 7;
        if monday > last {
            break;
        }
        for day in &weekdays {
            let date = monday + i64::from(*day);
            if date >= first_date && date <= last {
                dates.push(date);
            }
        }
        week += interval;
    }
    Ok(dates)
}

fn add(input: &mut Input) -> Result<Value, &'static str> {
    let item = input.item.clone().ok_or("add requires an item")?;
    validate_personal(&item)?;
    if input.school.iter().any(|existing| existing.id == item.id)
        || input.personal.iter().any(|existing| existing.id == item.id)
    {
        return Err("agenda ids must be unique");
    }
    let (conflicts, unresolved) = conflicts(&item, &input.school)?;
    if (!conflicts.is_empty() || unresolved) && !input.save_despite_conflict {
        return Ok(base(
            input,
            json!({
                "result": "conflict",
                "document_changed": false,
                "conflict_check_truncated": unresolved,
                "conflicts": conflicts
            }),
        ));
    }
    input.personal.push(item);
    Ok(saved(input, "saved", conflicts, unresolved))
}

fn update(input: &mut Input) -> Result<Value, &'static str> {
    let scope = input.scope.as_deref().ok_or("update requires a scope")?;
    let target = input
        .target_id
        .as_deref()
        .ok_or("update requires a target")?;
    let replacement = input.item.clone().ok_or("update requires an item")?;
    let index = personal_index(&input.personal, target)?;
    let current = input.personal[index].clone();
    if current.kind != replacement.kind {
        return Err("an update cannot change an event into a todo or the reverse");
    }
    let occurrence = required_occurrence(input, &current, scope)?;
    let mut created = replacement;
    created.id = match scope {
        "all" => current.id.clone(),
        "this" | "following" => format!(
            "{}@{}",
            current.id,
            format_date(beijing_days(occurrence.unwrap()))
        ),
        _ => return Err("scope must be this, following, or all"),
    };
    if scope == "this" {
        created.recurrence = Recurrence::default();
        created.exdates.clear();
        created.until = None;
    }
    validate_personal(&created)?;
    if input
        .personal
        .iter()
        .any(|item| item.id == created.id && item.id != current.id)
    {
        return Err("agenda ids must be unique");
    }
    let (conflicts, unresolved) = conflicts(&created, &input.school)?;
    if (!conflicts.is_empty() || unresolved) && !input.save_despite_conflict {
        return Ok(base(
            input,
            json!({"result":"conflict","document_changed":false,"conflicts":conflicts}),
        ));
    }
    match scope {
        "all" => input.personal[index] = created,
        "this" => {
            exclude_or_remove(&mut input.personal, index, occurrence.unwrap())?;
            input.personal.push(created);
        }
        "following" => {
            truncate_or_remove(&mut input.personal, index, occurrence.unwrap())?;
            input.personal.push(created);
        }
        _ => unreachable!("scope checked"),
    }
    Ok(saved(input, "updated", conflicts, unresolved))
}

fn delete(input: &mut Input) -> Result<Value, &'static str> {
    let scope = input.scope.as_deref().ok_or("delete requires a scope")?;
    let target = input
        .target_id
        .as_deref()
        .ok_or("delete requires a target")?;
    if input.school.iter().any(|item| item.id == target) {
        return Err("a school item can be hidden but not deleted");
    }
    let index = personal_index(&input.personal, target)?;
    let current = input.personal[index].clone();
    match scope {
        "all" => {
            input.personal.remove(index);
        }
        "this" | "following" => {
            let occurrence = required_occurrence(input, &current, scope)?.unwrap();
            if scope == "this" {
                exclude_or_remove(&mut input.personal, index, occurrence)?;
            } else {
                truncate_or_remove(&mut input.personal, index, occurrence)?;
            }
        }
        _ => return Err("scope must be this, following, or all"),
    }
    Ok(saved(input, "deleted", Vec::new(), false))
}

fn overlay(input: &mut Input) -> Result<Value, &'static str> {
    let target = input
        .target_id
        .as_deref()
        .ok_or("overlay requires a target")?;
    if input.completed.is_none() && input.hidden.is_none() && input.note.is_none() {
        return Err("overlay requires a completion, visibility, or note change");
    }
    if let Some(note) = input.note.as_deref()
        && note.chars().count() > 2000
    {
        return Err("a note must be at most 2000 characters");
    }
    if let Some(item) = input.school.iter_mut().find(|item| item.id == target) {
        apply_overlay(
            input.completed,
            input.hidden,
            input.note.clone(),
            &mut item.completed,
            &mut item.hidden,
            &mut item.note,
        );
        return Ok(saved(input, "overlayed", Vec::new(), false));
    }
    let item = input
        .personal
        .iter_mut()
        .find(|item| item.id == target)
        .ok_or("agenda item was not found")?;
    apply_overlay(
        input.completed,
        input.hidden,
        input.note.clone(),
        &mut item.completed,
        &mut item.hidden,
        &mut item.note,
    );
    Ok(saved(input, "overlayed", Vec::new(), false))
}

fn apply_overlay(
    completed: Option<bool>,
    hidden: Option<bool>,
    note: Option<String>,
    completed_out: &mut bool,
    hidden_out: &mut bool,
    note_out: &mut Option<String>,
) {
    if let Some(completed) = completed {
        *completed_out = completed;
    }
    if let Some(hidden) = hidden {
        *hidden_out = hidden;
    }
    if let Some(note) = note {
        *note_out = Some(note);
    }
}

fn required_occurrence(
    input: &Input,
    item: &Personal,
    scope: &str,
) -> Result<Option<i64>, &'static str> {
    if scope == "all" {
        if input.occurrence.is_some() {
            return Err("all-item changes do not take an occurrence");
        }
        return Ok(None);
    }
    let stamp = input
        .occurrence
        .as_deref()
        .ok_or("this and following scopes require an occurrence")?;
    let occurrence = parse_beijing(stamp).ok_or("occurrence must be a Beijing timestamp")?;
    let (hits, _) = expand(item, occurrence, occurrence + 1)?;
    if !hits.iter().any(|(start, _)| *start == occurrence) {
        return Err("occurrence is not part of the item");
    }
    Ok(Some(occurrence))
}

fn exclude_or_remove(
    items: &mut Vec<Personal>,
    index: usize,
    occurrence: i64,
) -> Result<(), &'static str> {
    if items[index].recurrence.kind == "none" {
        items.remove(index);
        return Ok(());
    }
    let date = format_date(beijing_days(occurrence));
    if !items[index]
        .exdates
        .iter()
        .any(|existing| existing == &date)
    {
        items[index].exdates.push(date);
    }
    Ok(())
}

fn truncate_or_remove(
    items: &mut Vec<Personal>,
    index: usize,
    occurrence: i64,
) -> Result<(), &'static str> {
    let (earlier, _) = expand(&items[index], occurrence - 366 * 86_400, occurrence)?;
    if earlier.is_empty() {
        items.remove(index);
    } else {
        items[index].until = Some(format_beijing(occurrence));
    }
    Ok(())
}

fn conflicts(item: &Personal, school: &[School]) -> Result<(Vec<Value>, bool), &'static str> {
    if item.kind != "event" {
        return Ok((Vec::new(), false));
    }
    let mut found = Vec::new();
    let mut unresolved = false;
    for course in school
        .iter()
        .filter(|item| item.source == "course" && !item.hidden)
    {
        let start = parse_beijing(course.start.as_deref().unwrap()).unwrap();
        let end = parse_beijing(course.end.as_deref().unwrap()).unwrap();
        let (hits, truncated) = expand(item, start, end)?;
        unresolved |= truncated;
        if !hits.is_empty() {
            found.push(json!({"id": course.id, "title": course.title, "start": course.start}));
        }
    }
    Ok((found, unresolved))
}

fn saved(input: &Input, result: &str, conflicts: Vec<Value>, unresolved: bool) -> Value {
    base(
        input,
        json!({
            "result": result,
            "document_changed": true,
            "conflict_check_truncated": unresolved,
            "conflicts": conflicts
        }),
    )
}

fn personal_index(items: &[Personal], id: &str) -> Result<usize, &'static str> {
    items
        .iter()
        .position(|item| item.id == id)
        .ok_or("personal item was not found")
}

fn required_range(input: &Input) -> Result<(i64, i64, &str), &'static str> {
    let view = match input.view.as_deref() {
        Some(view @ ("list" | "week" | "month")) => view,
        _ => return Err("view must be list, week, or month"),
    };
    let from = parse_beijing(input.range_start.as_deref().unwrap_or(""))
        .ok_or("range_start must be a Beijing timestamp")?;
    let to = parse_beijing(input.range_end.as_deref().unwrap_or(""))
        .ok_or("range_end must be a Beijing timestamp")?;
    if to <= from || to - from > MAX_RANGE {
        return Err("range must be positive and at most 400 days");
    }
    if let Some(sources) = &input.sources {
        if sources.is_empty()
            || sources.len() > SOURCES.len() + 1
            || sources
                .iter()
                .any(|source| source != "personal" && !SOURCES.contains(&source.as_str()))
        {
            return Err("sources contain an unknown value");
        }
    }
    if let Some(query) = &input.query
        && (query.is_empty() || query.chars().count() > 100)
    {
        return Err("query must be a non-empty search of at most 100 characters");
    }
    Ok((from, to, view))
}

fn occurrence_json(item: &Occurrence) -> Value {
    json!({
        "id": item.id,
        "source": item.source,
        "kind": item.kind,
        "title": item.title,
        "location": item.location,
        "note": item.note,
        "start": format_beijing(item.start),
        "end": item.end.map(format_beijing),
        "date": format_date(beijing_days(item.start)),
        "all_day": item.all_day,
        "completed": item.completed,
        "hidden": item.hidden,
        "undated": false
    })
}

fn render_ics(items: &[Occurrence], now: i64) -> Result<String, &'static str> {
    let mut lines = vec![
        "BEGIN:VCALENDAR".to_owned(),
        "VERSION:2.0".to_owned(),
        "PRODID:-//buaa-cli//agenda//EN".to_owned(),
        "CALSCALE:GREGORIAN".to_owned(),
        "X-WR-TIMEZONE:Asia/Shanghai".to_owned(),
    ];
    for item in items {
        let stamp = format!("DTSTAMP:{}", format_utc(now));
        let uid = format!(
            "UID:{}-{}",
            escape(&item.id),
            format_date(beijing_days(item.start)).replace('-', "")
        );
        if item.kind == "todo" {
            lines.extend([
                "BEGIN:VTODO".to_owned(),
                uid,
                stamp,
                format!("DUE:{}", ics_local(item.start)),
                format!("SUMMARY:{}", escape(&item.title)),
                format!(
                    "STATUS:{}",
                    if item.completed {
                        "COMPLETED"
                    } else {
                        "NEEDS-ACTION"
                    }
                ),
                "END:VTODO".to_owned(),
            ]);
        } else if item.all_day {
            lines.extend([
                "BEGIN:VEVENT".to_owned(),
                uid,
                stamp,
                format!("DTSTART;VALUE=DATE:{}", compact_date(item.start)),
                format!(
                    "DTEND;VALUE=DATE:{}",
                    compact_date(item.end.ok_or("event export lacks an end")?)
                ),
                format!("SUMMARY:{}", escape(&item.title)),
                "END:VEVENT".to_owned(),
            ]);
        } else {
            lines.extend([
                "BEGIN:VEVENT".to_owned(),
                uid,
                stamp,
                format!("DTSTART:{}", ics_local(item.start)),
                format!(
                    "DTEND:{}",
                    ics_local(item.end.ok_or("event export lacks an end")?)
                ),
                format!("SUMMARY:{}", escape(&item.title)),
                "END:VEVENT".to_owned(),
            ]);
        }
        if let Some(location) = &item.location {
            let index = lines.len() - 1;
            lines.insert(index, format!("LOCATION:{}", escape(location)));
        }
    }
    lines.push("END:VCALENDAR".to_owned());
    Ok(lines
        .into_iter()
        .map(|line| fold(&line))
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n")
}

fn ics_local(unix: i64) -> String {
    format_beijing(unix)
        .chars()
        .filter(|char| char.is_ascii_digit() || *char == 'T')
        .collect()
}

fn compact_date(unix: i64) -> String {
    format_date(beijing_days(unix)).replace('-', "")
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace(',', "\\,")
        .replace(';', "\\;")
}

fn fold(line: &str) -> String {
    let bytes = line.as_bytes();
    if bytes.len() <= 75 {
        return line.to_owned();
    }
    let mut folded = String::new();
    let mut position = 0;
    let mut first = true;
    while position < bytes.len() {
        let budget = if first { 75 } else { 74 };
        let mut cut = (position + budget).min(bytes.len());
        while cut > position && cut < bytes.len() && bytes[cut] & 0b1100_0000 == 0b1000_0000 {
            cut -= 1;
        }
        if !first {
            folded.push_str("\r\n ");
        }
        folded.push_str(&line[position..cut]);
        position = cut;
        first = false;
    }
    folded
}

fn base(input: &Input, mut value: Value) -> Value {
    value["network_performed"] = json!(false);
    value["campus_mutation"] = json!(false);
    value["school"] = serde_json::to_value(&input.school).unwrap_or(Value::Null);
    value["personal"] = serde_json::to_value(&input.personal).unwrap_or(Value::Null);
    value["credit"] = json!(CREDIT);
    value
}

fn ceil_div(value: i64, step: i64) -> i64 {
    (value + step - 1) / step
}

fn parse_optional(value: Option<&str>, field: &'static str) -> Result<Option<i64>, &'static str> {
    match value {
        None => Ok(None),
        Some(value) => parse_beijing(value).map(Some).ok_or(match field {
            "start" => "start must be a Beijing timestamp",
            "end" => "end must be a Beijing timestamp",
            "due" => "due must be a Beijing timestamp",
            _ => "timestamp must use Beijing time",
        }),
    }
}

fn validate_id(value: &str) -> Result<(), &'static str> {
    if (1..=80).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'@' | b'-')
        })
    {
        Ok(())
    } else {
        Err("ids must be 1 to 80 letters, digits, or _.:@-")
    }
}

fn validate_text(value: &str, allow_empty: bool) -> Result<(), &'static str> {
    if (!allow_empty && value.is_empty()) || value.chars().count() > 200 {
        Err("titles must be 1 to 200 characters")
    } else {
        Ok(())
    }
}

fn validate_optional(value: &Option<String>, limit: usize) -> Result<(), &'static str> {
    if value
        .as_ref()
        .is_some_and(|value| value.chars().count() > limit)
    {
        Err("a location or note is too long")
    } else {
        Ok(())
    }
}

fn invalid(message: &str) -> Value {
    json!({"error": "invalid_input", "message": message})
}

pub fn schema() -> Value {
    json!({
        "stdin": "one local agenda document and operation; school records are supplied by the caller and are never fetched or mutated remotely",
        "credit": CREDIT,
        "behavior": "https://github.com/BUAASubnet/UBAA/blob/3ac2ebd6c30162cd1ce1fc50964caa25ed22092f/docs/site/features/agenda.md",
        "operations": ["project", "upcoming", "add", "update", "delete", "overlay", "export", "sync"],
        "session": "agenda session --online performs one GSMIS authentication and one queryRcap.do read; update and delete endpoints are never called",
        "recurrence": ["none", "daily", "weekly", "weekdays", "teaching_week", "custom"],
        "time": "exact Asia/Shanghai timestamps; teaching weeks start from an explicit Monday",
        "sync": "sync returns cloud_sync_unverified and does not contact a drive or change the document",
        "export": "ICS is a snapshot. Undated items are omitted. Hidden items are omitted. Completed items require include_completed"
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    authorized: bool,
    username: String,
    password: String,
    intent: String,
    day: Option<String>,
}

fn session_error(code: &'static str, message: &'static str) -> Error {
    Error::new(code, message)
}

fn compact_day(day: &str) -> Result<String, Error> {
    let dashed = if day.len() == 8 && day.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{}-{}-{}", &day[..4], &day[4..6], &day[6..])
    } else {
        day.to_string()
    };
    if parse_date(&dashed).is_none() {
        return Err(session_error(
            "invalid_input",
            "agenda day is not a Beijing date",
        ));
    }
    Ok(dashed)
}

fn today_beijing() -> String {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    format_date(beijing_days(unix))
}

fn clock_hhmm(value: &str) -> Option<String> {
    let mut digits: String = value
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect();
    if digits.len() == 3 {
        digits.insert(0, '0');
    }
    if digits.len() != 4 && digits.len() != 6 {
        return None;
    }
    let hour: u32 = digits[..2].parse().ok()?;
    let minute: u32 = digits[2..4].parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(format!("{hour:02}:{minute:02}:00"))
}

fn finance_urls(body: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find("https://") {
        let candidate = &rest[start..];
        let end = candidate
            .find(|character: char| {
                !matches!(
                    character,
                    'A'..='Z'
                        | 'a'..='z'
                        | '0'..='9'
                        | '.'
                        | '-'
                        | '_'
                        | '/'
                        | '%'
                        | ':'
                        | '?'
                        | '&'
                        | '='
                        | '~'
                )
            })
            .unwrap_or(candidate.len());
        if let Ok(mut url) = url::Url::parse(&candidate[..end]) {
            let host = url.host_str().unwrap_or("").to_ascii_lowercase();
            let path = url.path().to_ascii_lowercase();
            if host.ends_with(".buaa.edu.cn")
                && (host.contains("cwxt")
                    || host.contains("gzcx")
                    || path.contains("cwxt")
                    || path.contains("gzcx")
                    || path.contains("salary"))
            {
                url.set_query(None);
                url.set_fragment(None);
                found.insert(url.to_string());
            }
        }
        let advance = end.max("https://".len());
        if advance >= candidate.len() {
            break;
        }
        rest = &candidate[advance..];
    }
    found.into_iter().collect()
}

fn finish_http(
    lease: RequestLease<'_>,
    status: u16,
    retry_after: Option<&str>,
    challenge: bool,
) -> Result<(), Error> {
    lease
        .finish(Outcome::Http {
            status,
            retry_after,
            challenge,
            network_failure: false,
        })
        .map_err(|_| session_error("governor_error", "cannot settle agenda response"))
}

fn settle_auth(lease: RequestLease<'_>, failure: &Error) -> Result<(), Error> {
    if matches!(
        failure.code,
        "governor_error" | "governor_denied" | "governor_unavailable"
    ) {
        drop(lease);
        return Ok(());
    }
    let settled = match failure.code {
        "auth_latched" => lease.finish(Outcome::CredentialRejected),
        "challenge_requires_human" => lease.finish(Outcome::CaptchaRequired),
        "relying_party_error" => lease.finish(Outcome::Http {
            status: 500,
            retry_after: None,
            challenge: false,
            network_failure: false,
        }),
        "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
        _ => lease.finish_without_request(),
    };
    settled.map_err(|_| {
        session_error(
            "governor_error",
            "cannot settle agenda authentication attempt",
        )
    })
}

/// Settle one read that already started inside the authentication attempt.
/// Every early return after the sign-on must reach this, so the governor
/// never keeps a pending attempt that only a crash could clear.
fn settle_read(lease: RequestLease<'_>, failure: &Error) -> Result<(), Error> {
    let settled = match failure.code {
        "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
        "challenge_requires_human" => lease.finish(Outcome::CaptchaRequired),
        "credential_echo" => lease.finish(Outcome::Http {
            status: 200,
            retry_after: None,
            challenge: false,
            network_failure: false,
        }),
        _ => lease.finish_without_request(),
    };
    settled.map_err(|_| {
        session_error(
            "governor_error",
            "cannot settle agenda authentication attempt",
        )
    })
}

/// One GSMIS sign-on and one `queryRcap.do` read. Update and delete endpoints
/// are never requested.
pub fn session(input_text: &str, online: bool) -> Result<Value, Error> {
    if input_text.len() > 32 * 1024 {
        return Err(session_error(
            "invalid_input",
            "agenda session input is invalid",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(input_text);
    let input: SessionInput = serde::Deserialize::deserialize(&mut deserializer)
        .map_err(|_| session_error("invalid_input", "agenda session input is invalid"))?;
    deserializer
        .end()
        .map_err(|_| session_error("invalid_input", "agenda session input is invalid"))?;
    if !input.authorized {
        return Err(session_error(
            "permission",
            "explicit authorization for one agenda authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if input.intent != format!("LOGIN {} agenda", input.username) {
        return Err(session_error(
            "invalid_input",
            "agenda session input is invalid",
        ));
    }
    let day = compact_day(input.day.as_deref().unwrap_or(&today_beijing()))?;
    if !online {
        return Err(session_error(
            "online_required",
            "agenda sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let client = cas::http_client()?;
    let governor = Governor::open()
        .map_err(|_| session_error("governor_error", "shared request admission unavailable"))?;
    let mut lease = net::acquire_kind(&governor, RequestKind::Authentication)?;
    let mut observed = None;
    let prepared = cas::authenticate_service(&mut lease, &client, CasService::Gsmis, credentials)
        .and_then(|mut service| {
            let portal = url::Url::parse(AGENDA_PORTAL_URL)
                .map_err(|_| session_error("invalid_input", "agenda session input is invalid"))?;
            let (cookie, expiry) = service.cookie_header_for_transmission(&portal)?;
            let cookie = cookie.ok_or_else(|| {
                session_error(
                    "authentication_unconfirmed",
                    "the agenda application cookie is missing; no entry was sent",
                )
            })?;
            admit_session_read(&mut lease)?;
            if expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
                return Err(session_error(
                    "scoped_cookie_unusable",
                    "the agenda cookie expired before application entry; no request was sent",
                ));
            }
            let mut request = client
                .get(AGENDA_PORTAL_URL)
                .header("Cookie", cookie)
                .header("Accept", "text/html")
                .header("Referer", AGENDA_PORTAL_URL)
                .timeout(std::time::Duration::from_secs(45))
                .header("Accept-Encoding", "identity")
                .build()
                .map_err(|_| session_error("invalid_input", "agenda session input is invalid"))?;
            if let Some(value) = request.headers_mut().get_mut("cookie") {
                value.set_sensitive(true);
            }
            Ok((service, portal, request))
        });
    let (mut service, portal, request) = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            settle_auth(lease, &failure)?;
            return Err(failure);
        }
    };
    let response = match lease.start_request(|| Some(client.execute(request))) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) | Ok(None) => {
            lease
                .finish(Outcome::NetworkFailure)
                .map_err(|_| session_error("governor_error", "cannot settle agenda request"))?;
            return Err(session_error(
                "network_error",
                "agenda portal entry failed; no schedule read was sent",
            ));
        }
        Err(FollowupError::Governor(_)) => {
            return Err(session_error(
                "governor_error",
                "request safety admission failed; pending outcome retained",
            ));
        }
    };
    let portal_body = match receive_context_response(
        response,
        &mut lease,
        &mut service,
        &portal,
        &mut observed,
    ) {
        Ok(body) => body,
        Err(failure) => {
            settle_read(lease, &failure)?;
            return Err(failure);
        }
    };
    if let Err(failure) = screen_context_response(&portal_body, &input.password, &service) {
        finish_http(
            lease,
            portal_body.status,
            portal_body.retry_after.as_deref(),
            portal_body.challenge,
        )?;
        return Err(failure);
    }
    let mentions_finance = portal_body
        .body
        .windows("财务".len())
        .any(|window| window == "财务".as_bytes());
    let links = finance_urls(&portal_body.body);
    if portal_body.status != 200 {
        finish_http(
            lease,
            portal_body.status,
            portal_body.retry_after.as_deref(),
            portal_body.challenge,
        )?;
        return Ok(json!({
            "result": "schedule_endpoint_absent",
            "service": "gsmis",
            "http_status": portal_body.status,
            "network_performed": true,
            "write_operations_performed": false,
            "mentions_finance": mentions_finance,
            "finance_urls": links,
            "credit": CREDIT
        }));
    }
    let query_url = match url::Url::parse(AGENDA_QUERY_URL) {
        Ok(url) => url,
        Err(_) => {
            let failure = session_error("invalid_input", "agenda session input is invalid");
            settle_read(lease, &failure)?;
            return Err(failure);
        }
    };
    let (cookie, expiry) = match service.cookie_header_for_transmission(&query_url) {
        Ok(cookie) => cookie,
        Err(failure) => {
            settle_read(lease, &failure)?;
            return Err(failure);
        }
    };
    let cookie = match cookie {
        Some(cookie) => cookie,
        None => {
            finish_http(lease, portal_body.status, None, false)?;
            return Err(session_error(
                "auth_latched",
                "the agenda session has no usable cookie; no schedule read was sent",
            ));
        }
    };
    admit_session_read(&mut lease)?;
    if expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
        lease
            .finish_without_request()
            .map_err(|_| session_error("governor_error", "cannot release agenda request"))?;
        return Err(session_error(
            "scoped_cookie_unusable",
            "the agenda cookie expired before the schedule read; no request was sent",
        ));
    }
    let compact = day.replace('-', "");
    let mut query =
        match timetable::session_request(&client, AGENDA_QUERY_URL, cookie, AGENDA_PORTAL_URL)
            .form(&[("day", compact.as_str())])
            .timeout(std::time::Duration::from_secs(45))
            .header("Accept-Encoding", "identity")
            .build()
        {
            Ok(query) => query,
            Err(_) => {
                let failure = session_error("invalid_input", "agenda session input is invalid");
                settle_read(lease, &failure)?;
                return Err(failure);
            }
        };
    if let Some(value) = query.headers_mut().get_mut("cookie") {
        value.set_sensitive(true);
    }
    let response = match lease.start_request(|| Some(client.execute(query))) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) | Ok(None) => {
            lease
                .finish(Outcome::NetworkFailure)
                .map_err(|_| session_error("governor_error", "cannot settle agenda request"))?;
            return Err(session_error(
                "network_error",
                "agenda schedule read failed; no automatic retry",
            ));
        }
        Err(FollowupError::Governor(_)) => {
            return Err(session_error(
                "governor_error",
                "request safety admission failed; pending outcome retained",
            ));
        }
    };
    let body = match receive_context_response(
        response,
        &mut lease,
        &mut service,
        &query_url,
        &mut observed,
    ) {
        Ok(body) => body,
        Err(failure) => {
            settle_read(lease, &failure)?;
            return Err(failure);
        }
    };
    if let Err(failure) = screen_context_response(&body, &input.password, &service) {
        finish_http(
            lease,
            body.status,
            body.retry_after.as_deref(),
            body.challenge,
        )?;
        return Err(failure);
    }
    finish_http(
        lease,
        body.status,
        body.retry_after.as_deref(),
        body.challenge,
    )?;
    if body.status != 200 {
        return Err(session_error(
            "authentication_unconfirmed",
            "agenda schedule read was refused",
        ));
    }
    let mut output = parse_live_schedule(&day, &body.body, &input.username)?;
    output["mentions_finance"] = json!(mentions_finance);
    output["finance_urls"] = json!(links);
    output["credit"] = json!(CREDIT);
    Ok(output)
}

fn parse_live_schedule(day: &str, bytes: &[u8], username: &str) -> Result<Value, Error> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        session_error(
            "upstream_parse",
            "agenda schedule was not the reviewed JSON object",
        )
    })?;
    if value.get("success") != Some(&Value::Bool(true)) {
        return Err(session_error(
            "upstream_parse",
            "agenda schedule did not report success",
        ));
    }
    let Some(items) = value.get("res").and_then(Value::as_array) else {
        return Err(session_error(
            "upstream_parse",
            "agenda schedule was not the reviewed JSON object",
        ));
    };
    let mut events = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let title = item
            .get("TITLE")
            .and_then(Value::as_str)
            .filter(|title| !title.is_empty())
            .or_else(|| item.get("CONTENT").and_then(Value::as_str))
            .unwrap_or("");
        let start_text = item.get("KSSJ").and_then(field_text);
        let end_text = item.get("JSSJ").and_then(field_text);
        let start = start_text.as_deref().and_then(clock_hhmm);
        let end = end_text.as_deref().and_then(clock_hhmm);
        let (Some(start), Some(end)) = (start, end) else {
            continue;
        };
        if title.is_empty() || title.chars().count() > 200 {
            continue;
        }
        let id = match item.get("WID") {
            Some(Value::String(id)) if !id.is_empty() => id.clone(),
            Some(Value::Number(id)) => id.to_string(),
            _ => format!("gsmis-{day}-{index}"),
        };
        let location = item.get("ADDRESS").and_then(Value::as_str).unwrap_or("");
        if !username.is_empty()
            && (title.contains(username) || location.contains(username) || id.contains(username))
        {
            continue;
        }
        let type_code = item
            .get("TYPE")
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
            })
            .unwrap_or(-1);
        events.push(json!({
            "id": id,
            "origin": match type_code { 0 => "course", 1 => "personal", 2 => "exam", _ => "other" },
            "type_code": type_code,
            "title": title,
            "start": format!("{day}T{start}+08:00"),
            "end": format!("{day}T{end}+08:00"),
            "location": location
        }));
    }
    Ok(json!({
        "result": "parsed",
        "service": "gsmis",
        "day": day,
        "term_label": value.get("xnxq").and_then(Value::as_str).unwrap_or(""),
        "event_count": events.len(),
        "source_count": items.len(),
        "events": events,
        "network_performed": true,
        "write_operations_performed": false
    }))
}

fn field_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_live_schedule;
    use super::{run, session};
    use serde_json::{Value, json};

    fn event(id: &str, title: &str, start: &str, end: &str, recurrence: Value) -> Value {
        json!({
            "id": id,
            "kind": "event",
            "title": title,
            "start": start,
            "end": end,
            "recurrence": recurrence
        })
    }

    fn course(start: &str, end: &str) -> Value {
        json!({
            "id": "course-1",
            "source": "course",
            "title": "高等数学",
            "start": start,
            "end": end
        })
    }

    fn document(school: Vec<Value>, personal: Vec<Value>, operation: &str, extra: Value) -> Value {
        let mut input = json!({
            "now": "2026-09-01T08:00:00+08:00",
            "operation": operation,
            "school": school,
            "personal": personal
        });
        for (key, value) in extra.as_object().unwrap() {
            input[key] = value.clone();
        }
        run(&input.to_string())
    }

    #[test]
    fn teaching_weeks_skip_even_weeks_and_named_dates() {
        let item = event(
            "lab",
            "实验",
            "2026-09-07T10:00:00+08:00",
            "2026-09-07T11:00:00+08:00",
            json!({
                "kind": "teaching_week",
                "first_monday": "2026-09-07",
                "start_week": 1,
                "end_week": 4,
                "parity": "odd",
                "weekday": 0,
                "skip_dates": ["2026-09-21"]
            }),
        );
        let output = document(
            vec![],
            vec![item],
            "project",
            json!({
                "view": "week",
                "range_start": "2026-09-01T00:00:00+08:00",
                "range_end": "2026-10-01T00:00:00+08:00"
            }),
        );
        let dates: Vec<_> = output["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["date"].as_str().unwrap())
            .collect();
        assert_eq!(dates, vec!["2026-09-07"]);
        let mut hidden = event(
            "hid",
            "隐藏事项",
            "2026-09-08T10:00:00+08:00",
            "2026-09-08T11:00:00+08:00",
            json!({"kind":"none"}),
        );
        hidden["hidden"] = json!(true);
        let range = json!({"view":"list","range_start":"2026-09-01T00:00:00+08:00","range_end":"2026-10-01T00:00:00+08:00"});
        let concealed = document(vec![], vec![hidden.clone()], "project", range.clone());
        assert!(concealed["occurrences"].as_array().unwrap().is_empty());
        let mut range_with_hidden = range;
        range_with_hidden["show_hidden"] = json!(true);
        let shown = document(vec![], vec![hidden], "project", range_with_hidden);
        assert_eq!(shown["occurrences"][0]["id"], "hid");
    }

    #[test]
    fn fortnightly_projection_conflict_and_overlay_keep_school_text() {
        let item = event(
            "p1",
            "自习",
            "2026-09-07T10:00:00+08:00",
            "2026-09-07T11:00:00+08:00",
            json!({"kind":"weekly","interval":2,"weekdays":[0]}),
        );
        let projected = document(
            vec![],
            vec![item.clone()],
            "project",
            json!({"view":"list","range_start":"2026-09-01T00:00:00+08:00","range_end":"2026-10-01T00:00:00+08:00"}),
        );
        let dates: Vec<_> = projected["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["date"].as_str().unwrap())
            .collect();
        assert_eq!(dates, vec!["2026-09-07", "2026-09-21"]);
        let blocked = document(
            vec![course(
                "2026-09-07T10:00:00+08:00",
                "2026-09-07T11:30:00+08:00",
            )],
            vec![],
            "add",
            json!({"item": item}),
        );
        assert_eq!(blocked["result"], "conflict");
        assert!(blocked["personal"].as_array().unwrap().is_empty());
        let mut hidden = course("2026-09-07T10:00:00+08:00", "2026-09-07T11:30:00+08:00");
        hidden["hidden"] = json!(true);
        let saved = document(vec![hidden], vec![], "add", json!({"item": item}));
        assert_eq!(saved["result"], "saved");
        let noted = document(
            vec![course(
                "2026-09-07T10:00:00+08:00",
                "2026-09-07T11:30:00+08:00",
            )],
            vec![],
            "overlay",
            json!({"target_id":"course-1","completed":true,"note":"只在本地"}),
        );
        assert_eq!(noted["school"][0]["title"], "高等数学");
        assert_eq!(noted["school"][0]["completed"], true);
        assert_eq!(noted["campus_mutation"], false);
    }

    #[test]
    fn deletion_scopes_and_export_omit_undated_and_fold_lines() {
        let item = event(
            "p1",
            &"日程".repeat(40),
            "2026-09-07T10:00:00+08:00",
            "2026-09-07T11:00:00+08:00",
            json!({"kind":"weekly","interval":1,"weekdays":[0]}),
        );
        let following = document(
            vec![],
            vec![item.clone()],
            "delete",
            json!({"target_id":"p1","scope":"following","occurrence":"2026-09-21T10:00:00+08:00"}),
        );
        let remaining = document(
            vec![],
            following["personal"].as_array().unwrap().clone(),
            "project",
            json!({"view":"month","range_start":"2026-09-01T00:00:00+08:00","range_end":"2026-10-01T00:00:00+08:00"}),
        );
        let dates: Vec<_> = remaining["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["date"].as_str().unwrap())
            .collect();
        assert_eq!(dates, vec!["2026-09-07", "2026-09-14"]);
        let undated = json!({"id":"todo-1","kind":"todo","title":"无日期","undated":true});
        let exported = document(
            vec![],
            vec![item, undated.clone()],
            "export",
            json!({"view":"list","range_start":"2026-09-07T00:00:00+08:00","range_end":"2026-09-08T00:00:00+08:00","include_completed":false}),
        );
        assert_eq!(exported["omitted_undated"], 1);
        assert_eq!(exported["exported"], 1);
        let ics = exported["ics"].as_str().unwrap();
        assert!(ics.contains("\r\n"));
        assert!(!ics.replace("\r\n", "\n").contains('\r'));
        assert!(ics.lines().all(|line| line.len() <= 75));
        assert!(ics.contains("SUMMARY:"));
        let _ = undated;
        let blocked = document(vec![], vec![], "sync", json!({}));
        assert_eq!(blocked["result"], "blocked");
        assert_eq!(blocked["reason"], "cloud_sync_unverified");
        assert_eq!(blocked["document_changed"], false);
        assert_eq!(blocked["network_performed"], false);
    }

    #[test]
    fn upcoming_uses_eight_days_and_keeps_undated_todos() {
        let soon = event(
            "soon",
            "近期",
            "2026-11-29T23:00:00+08:00",
            "2026-11-30T00:00:00+08:00",
            json!({"kind":"none"}),
        );
        let later = event(
            "later",
            "超出",
            "2026-11-30T00:00:00+08:00",
            "2026-11-30T01:00:00+08:00",
            json!({"kind":"none"}),
        );
        let output = document(
            vec![],
            vec![
                soon,
                later,
                json!({"id":"loose","kind":"todo","title":"随时","undated":true}),
            ],
            "upcoming",
            json!({"now":"2026-11-22T00:00:00+08:00"}),
        );
        let ids: Vec<_> = output["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["loose", "soon"]);
    }

    #[test]
    fn session_without_online_does_not_authenticate() {
        let error = session(
            r#"{"authorized":true,"username":"student","password":"secret","intent":"LOGIN student agenda"}"#,
            false,
        )
        .expect_err("offline session must refuse");
        assert_eq!(error.code, "online_required");
    }

    #[test]
    fn null_event_id_still_projects_without_the_account_field() {
        let output = parse_live_schedule(
            "2026-11-16",
            r#"{"success":true,"xnxq":" 第11周","res":[{"TITLE":"课程","KSSJ":"083000","JSSJ":"101500","TYPE":0,"WID":null,"XH":"student"}]}"#.as_bytes(),
            "student",
        )
        .expect("schedule");
        assert_eq!(output["source_count"], 1);
        assert_eq!(output["event_count"], 1);
        assert_eq!(output["events"][0]["origin"], "course");
        assert_eq!(output["events"][0]["start"], "2026-11-16T08:30:00+08:00");
        assert!(!output.to_string().contains("student"));
    }
}

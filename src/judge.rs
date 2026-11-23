//! Local projection of operator-supplied 希冀 assignment records.
//!
//! Grouping, the default unfinished and unexpired view, sort, search, and
//! per-problem detail follow the behavior described by BUAASubnet/UBAA
//! `docs/site/features/judge.md` at `3ac2ebd6c30162cd1ce1fc50964caa25ed22092f`
//! (MIT, © 2026 MooreFoss). This is original code: it does not copy UBAA, does
//! not contact the campus judge, and does not submit work. A read failure is
//! never reported as an empty assignment list.

use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Read;

use crate::civil_time::parse_beijing;
use crate::{
    governor::{FollowupError, Governor, Outcome, RequestKind, RequestLease},
    net::{self, Error},
    recordings::session::{self as cas, CasService, SsoCredentials},
    timetable::admit_session_read,
};

const JUDGE_ORIGIN: &str = "https://judge.buaa.edu.cn";
const JUDGE_COURSE_LIST: &str = "https://judge.buaa.edu.cn/courselist.jsp?courseID=";
const JUDGE_ASSIGNMENT_LIST: &str = "https://judge.buaa.edu.cn/assignment/index.jsp";
const JUDGE_BODY_LIMIT: u64 = 512 * 1024;
const LIVE_COURSES: usize = 6;
const LIVE_DETAILS: usize = 20;

const CREDIT: &str =
    "BUAASubnet/UBAA@3ac2ebd6c30162cd1ce1fc50964caa25ed22092f (MIT, © 2026 MooreFoss)";
const MAX_ASSIGNMENTS: usize = 200;
const MAX_PROBLEMS: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    now: String,
    query: Option<String>,
    #[serde(default = "due_sort")]
    sort: String,
    #[serde(default = "ascending")]
    order: String,
    #[serde(default)]
    include_completed: bool,
    #[serde(default)]
    include_expired: bool,
    assignment_id: Option<String>,
    read_error: Option<String>,
    assignments: Vec<Assignment>,
}

fn due_sort() -> String {
    "due".to_owned()
}

fn ascending() -> String {
    "asc".to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    course_id: String,
    course_name: String,
    assignment_id: String,
    title: String,
    start: Option<String>,
    due: Option<String>,
    problems: Vec<Problem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Problem {
    name: String,
    score: Option<i64>,
    max_score: Option<i64>,
    submitted: bool,
}

struct Prepared {
    course_id: String,
    course_name: String,
    assignment_id: String,
    title: String,
    start: Option<i64>,
    due: Option<i64>,
    status: &'static str,
    status_text: &'static str,
    submitted_count: usize,
    total_problems: usize,
    my_score: Option<i64>,
    max_score: Option<i64>,
    problems: Vec<Problem>,
}

pub fn query(input: &str) -> Value {
    let parsed = match serde_json::from_str::<Query>(input) {
        Ok(value) => value,
        Err(_) => return invalid("input must be one judge JSON object"),
    };
    match project(parsed) {
        Ok(value) => value,
        Err(message) => invalid(message),
    }
}

fn project(query: Query) -> Result<Value, &'static str> {
    let now = parse_beijing(&query.now).ok_or("now must be a Beijing timestamp")?;
    if let Some(error) = query.read_error.as_deref() {
        if error.is_empty() || error.chars().count() > 300 {
            return Err("read_error must be a short non-empty reason");
        }
        return Ok(json!({
            "result": "read_failed",
            "fallback_reason": error,
            "network_performed": false,
            "submission_performed": false,
            "query_only": true,
            "assignments": null,
            "groups": null,
            "credit": CREDIT
        }));
    }
    if query.assignments.len() > MAX_ASSIGNMENTS {
        return Err("too many assignments");
    }
    let sort_due = match query.sort.as_str() {
        "due" => true,
        "start" => false,
        _ => return Err("sort must be due or start"),
    };
    let ascending = match query.order.as_str() {
        "asc" => true,
        "desc" => false,
        _ => return Err("order must be asc or desc"),
    };
    if let Some(query) = query.query.as_deref()
        && (query.is_empty() || query.chars().count() > 100)
    {
        return Err("query must be a non-empty search of at most 100 characters");
    }
    let mut prepared = Vec::with_capacity(query.assignments.len());
    let mut seen_assignments = std::collections::BTreeSet::new();
    let mut course_names = std::collections::BTreeMap::new();
    for assignment in query.assignments {
        validate_label(&assignment.course_id, "course_id")?;
        validate_label(&assignment.course_name, "course_name")?;
        validate_label(&assignment.assignment_id, "assignment_id")?;
        validate_label(&assignment.title, "title")?;
        if !seen_assignments.insert(assignment.assignment_id.clone()) {
            return Err("assignment_id must be unique");
        }
        match course_names.get(&assignment.course_id) {
            Some(name) if *name != assignment.course_name => {
                return Err("one course_id cannot have two course names");
            }
            None => {
                course_names.insert(assignment.course_id.clone(), assignment.course_name.clone());
            }
            Some(_) => {}
        }
        prepared.push(prepare(assignment)?);
    }
    if let Some(id) = query.assignment_id.as_deref() {
        let found = prepared
            .iter()
            .find(|assignment| assignment.assignment_id == id);
        return Ok(match found {
            Some(assignment) => json!({
                "result": "detail",
                "network_performed": false,
                "submission_performed": false,
                "query_only": true,
                "detail": detail(assignment),
                "credit": CREDIT
            }),
            None => json!({
                "result": "not_found",
                "network_performed": false,
                "submission_performed": false,
                "query_only": true,
                "detail": null,
                "credit": CREDIT
            }),
        });
    }
    prepared.retain(|assignment| {
        let matches = query.query.as_ref().is_none_or(|query| {
            assignment.course_name.contains(query) || assignment.title.contains(query)
        });
        matches
            && visible(
                assignment,
                now,
                query.include_completed,
                query.include_expired,
            )
    });
    prepared.sort_by(|left, right| {
        let key = |assignment: &Prepared| {
            let time = if sort_due {
                assignment.due
            } else {
                assignment.start
            };
            (
                time.is_none(),
                if ascending {
                    time
                } else {
                    time.map(|time| -time)
                },
                assignment.title.clone(),
                assignment.assignment_id.clone(),
            )
        };
        key(left).cmp(&key(right))
    });
    let mut groups = Vec::new();
    for assignment in &prepared {
        if groups
            .last()
            .and_then(|group: &Value| group.get("course_id"))
            .and_then(Value::as_str)
            != Some(assignment.course_id.as_str())
        {
            groups.push(json!({
                "course_id": assignment.course_id,
                "course_name": assignment.course_name,
                "assignments": []
            }));
        }
        groups
            .last_mut()
            .and_then(|group| group.get_mut("assignments"))
            .and_then(Value::as_array_mut)
            .expect("group was just inserted")
            .push(summary(assignment));
    }
    Ok(json!({
        "result": "projected",
        "network_performed": false,
        "submission_performed": false,
        "query_only": true,
        "coverage": "supplied_records_only",
        "filter": {
            "sort": if sort_due { "due" } else { "start" },
            "order": if ascending { "asc" } else { "desc" },
            "include_completed": query.include_completed,
            "include_expired": query.include_expired,
            "query": query.query
        },
        "groups": groups,
        "credit": CREDIT
    }))
}

fn prepare(assignment: Assignment) -> Result<Prepared, &'static str> {
    if assignment.problems.len() > MAX_PROBLEMS {
        return Err("too many problems");
    }
    let start = match assignment.start.as_deref() {
        None => None,
        Some(value) => Some(parse_beijing(value).ok_or("start must be a Beijing timestamp")?),
    };
    let due = match assignment.due.as_deref() {
        None => None,
        Some(value) => Some(parse_beijing(value).ok_or("due must be a Beijing timestamp")?),
    };
    if let (Some(start), Some(due)) = (start, due)
        && due < start
    {
        return Err("due must not precede start");
    }
    let mut submitted_count = 0;
    let mut my_score = Some(0);
    let mut max_score = Some(0);
    for problem in &assignment.problems {
        validate_label(&problem.name, "problem name")?;
        match (problem.score, problem.max_score) {
            (Some(score), Some(max)) if (0..=max).contains(&score) && max >= 0 => {}
            (None, Some(max)) if max >= 0 && !problem.submitted => {}
            (None, None) if !problem.submitted => {}
            (None, Some(max)) if max >= 0 && problem.submitted => {}
            _ => return Err("problem score must be between zero and its maximum"),
        }
        if problem.submitted {
            submitted_count += 1;
            if problem.score.is_none() {
                my_score = None;
            }
        } else if problem.score.is_some() {
            return Err("an unsubmitted problem cannot already have a score");
        }
        match (my_score, problem.score) {
            (Some(total), Some(score)) if problem.submitted => my_score = Some(total + score),
            _ => {}
        }
        match (max_score, problem.max_score) {
            (Some(total), Some(score)) => max_score = Some(total + score),
            _ => max_score = None,
        }
    }
    let (status, status_text) = if assignment.problems.is_empty() {
        ("unknown", "未知")
    } else if submitted_count == 0 {
        ("unsubmitted", "未提交")
    } else if submitted_count == assignment.problems.len() {
        ("submitted", "已提交")
    } else {
        ("partial", "部分提交")
    };
    Ok(Prepared {
        course_id: assignment.course_id,
        course_name: assignment.course_name,
        assignment_id: assignment.assignment_id,
        title: assignment.title,
        start,
        due,
        status,
        status_text,
        submitted_count,
        total_problems: assignment.problems.len(),
        my_score: if assignment.problems.is_empty() {
            None
        } else {
            my_score
        },
        max_score: if assignment.problems.is_empty() {
            None
        } else {
            max_score
        },
        problems: assignment.problems,
    })
}

fn visible(
    assignment: &Prepared,
    now: i64,
    include_completed: bool,
    include_expired: bool,
) -> bool {
    let expired = assignment.due.is_some_and(|due| due < now);
    if expired {
        return include_expired;
    }
    assignment.status != "submitted" || include_completed
}

fn summary(assignment: &Prepared) -> Value {
    json!({
        "course_id": assignment.course_id,
        "course_name": assignment.course_name,
        "assignment_id": assignment.assignment_id,
        "title": assignment.title,
        "start": assignment.start.map(crate::civil_time::format_beijing),
        "due": assignment.due.map(crate::civil_time::format_beijing),
        "status": assignment.status,
        "status_text": assignment.status_text,
        "submitted_count": assignment.submitted_count,
        "total_problems": assignment.total_problems,
        "my_score": assignment.my_score,
        "max_score": assignment.max_score
    })
}

fn detail(assignment: &Prepared) -> Value {
    let mut value = summary(assignment);
    value["problems"] = json!(
        assignment
            .problems
            .iter()
            .map(|problem| {
                let (status, status_text) = if problem.submitted {
                    ("submitted", "已提交")
                } else {
                    ("unsubmitted", "未提交")
                };
                json!({
                    "name": problem.name,
                    "score": problem.score,
                    "max_score": problem.max_score,
                    "status": status,
                    "status_text": status_text
                })
            })
            .collect::<Vec<_>>()
    );
    value
}

fn validate_label(value: &str, field: &'static str) -> Result<(), &'static str> {
    if value.is_empty() || value.chars().count() > 200 {
        return Err(match field {
            "course_id" | "assignment_id" => "identifiers must be 1 to 200 characters",
            _ => "text fields must be 1 to 200 characters",
        });
    }
    Ok(())
}

fn invalid(message: &str) -> Value {
    json!({"error": "invalid_input", "message": message})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    authorized: bool,
    username: String,
    password: String,
    intent: String,
}

fn session_error(code: &'static str, message: &'static str) -> Error {
    Error::new(code, message)
}

fn decode(body: &[u8], content_type: Option<&str>) -> String {
    if let Ok(text) = std::str::from_utf8(body) {
        return text.to_owned();
    }
    let declared_gbk = content_type
        .map(|value| value.to_ascii_lowercase().contains("gb"))
        .unwrap_or(false);
    let (text, _, _) = if declared_gbk {
        encoding_rs::GBK.decode(body)
    } else {
        encoding_rs::UTF_8.decode(body)
    };
    text.into_owned()
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
        "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
        _ => lease.finish_without_request(),
    };
    settled.map_err(|_| session_error("governor_error", "cannot settle judge authentication"))
}

fn get_page(
    client: &reqwest::blocking::Client,
    lease: &mut RequestLease<'_>,
    service: &mut cas::ServiceSession,
    url_text: &str,
    password: &str,
) -> Result<String, Error> {
    let url = url::Url::parse(url_text)
        .map_err(|_| session_error("invalid_input", "judge URL is not admissible"))?;
    let (cookie, expiry) = service.cookie_header_for_transmission(&url)?;
    let cookie = cookie.ok_or_else(|| {
        session_error(
            "auth_latched",
            "the judge session has no usable cookie; no read was sent",
        )
    })?;
    admit_session_read(lease)?;
    if expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
        return Err(session_error(
            "scoped_cookie_unusable",
            "the judge cookie expired before the read; no request was sent",
        ));
    }
    let mut request = client
        .get(url_text)
        .header("Cookie", cookie)
        .header("Accept", "text/html")
        .header("Referer", JUDGE_ORIGIN)
        .timeout(std::time::Duration::from_secs(45))
        .header("Accept-Encoding", "identity")
        .build()
        .map_err(|_| session_error("invalid_input", "judge request is not admissible"))?;
    if let Some(value) = request.headers_mut().get_mut("cookie") {
        value.set_sensitive(true);
    }
    let response = match lease.start_request(|| Some(client.execute(request))) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) | Ok(None) => {
            return Err(session_error(
                "network_error",
                "judge read failed; no automatic retry",
            ));
        }
        Err(FollowupError::Governor(_)) => {
            return Err(session_error(
                "governor_error",
                "request safety admission failed; pending outcome retained",
            ));
        }
    };
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let challenge = response
        .headers()
        .iter()
        .any(|(name, value)| net::challenge_header(name.as_str(), value.as_bytes()));
    if lease
        .observe_http_many(
            status,
            response
                .headers()
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            challenge,
        )
        .is_err()
    {
        return Err(session_error(
            "governor_error",
            "cannot persist judge response",
        ));
    }
    service.absorb_judge_headers(&url, response.headers())?;
    let mut body = Vec::new();
    response
        .take(JUDGE_BODY_LIMIT)
        .read_to_end(&mut body)
        .map_err(|_| session_error("network_error", "judge body read failed"))?;
    if challenge
        || crate::html::assess_challenge_body(&body, content_type.as_deref(), true)
            == crate::html::ChallengeAssessment::Detected
    {
        return Err(session_error(
            "challenge_requires_human",
            "judge read requires review",
        ));
    }
    if net::carries_secret(&body, password) {
        return Err(session_error(
            "credential_echo",
            "judge response echoes the sign-on secret",
        ));
    }
    // Judge pages URL-rewrite the session id into their links. The body is
    // never exported, and the projection is screened again before it leaves
    // this invocation, so an in-page rewrite is not by itself a leak.
    if status != 200 {
        return Err(session_error(
            "authentication_unconfirmed",
            "judge read was refused",
        ));
    }
    Ok(decode(&body, content_type.as_deref()))
}

fn digits_after(text: &str, marker: &str) -> Option<String> {
    let rest = &text[text.find(marker)? + marker.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn anchor_text(anchor: scraper::ElementRef<'_>) -> String {
    anchor
        .text()
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn courses(html: &str) -> Vec<(String, String)> {
    use scraper::{Html, Selector};
    let selector = Selector::parse("a[href]").expect("static judge selector");
    let document = Html::parse_document(html);
    let mut found: Vec<(String, String)> = Vec::new();
    for anchor in document.select(&selector) {
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        let Some(id) = digits_after(href, "courselist.jsp?courseID=") else {
            continue;
        };
        if id == "0" || found.iter().any(|(course, _)| course == &id) {
            continue;
        }
        let name = anchor_text(anchor);
        if !name.is_empty() {
            found.push((id, name));
        }
    }
    found
}

fn assignments(html: &str) -> Vec<(String, String)> {
    use scraper::{Html, Selector};
    let selector = Selector::parse("a[href]").expect("static judge selector");
    let document = Html::parse_document(html);
    let mut found: Vec<(String, String)> = Vec::new();
    for anchor in document.select(&selector) {
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        if href.contains("problemContent") || href.contains("judgeDetails") {
            continue;
        }
        let Some(id) = digits_after(href, "assignID=") else {
            continue;
        };
        if found.iter().any(|(assignment, _)| assignment == &id) {
            continue;
        }
        let title = anchor_text(anchor);
        if !title.is_empty() {
            found.push((id, title));
        }
    }
    found
}

fn beijing_stamp(raw: &str) -> Option<String> {
    let text = raw.trim();
    let (date, clock) = text.split_once(' ')?;
    let clock = if clock.matches(':').count() == 1 {
        format!("{clock}:00")
    } else {
        clock.to_owned()
    };
    let stamp = format!("{date}T{clock}+08:00");
    parse_beijing(&stamp).map(|_| stamp)
}

fn digit_at(chars: &[char], at: usize, width: usize) -> bool {
    chars
        .get(at..at + width)
        .is_some_and(|slice| slice.iter().all(char::is_ascii_digit))
}

/// Every `YYYY-MM-DD HH:MM[:SS]` stamp in order, without assuming a label.
fn stamps(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 16 <= chars.len() {
        let date = digit_at(&chars, index, 4)
            && chars[index + 4] == '-'
            && digit_at(&chars, index + 5, 2)
            && chars[index + 7] == '-'
            && digit_at(&chars, index + 8, 2);
        if date {
            let mut clock = index + 10;
            while chars.get(clock) == Some(&' ') {
                clock += 1;
            }
            if digit_at(&chars, clock, 2)
                && chars.get(clock + 2) == Some(&':')
                && digit_at(&chars, clock + 3, 2)
            {
                let mut end = clock + 5;
                if chars.get(end) == Some(&':') && digit_at(&chars, end + 1, 2) {
                    end += 3;
                }
                let day: String = chars[index..index + 10].iter().collect();
                let time: String = chars[clock..end].iter().collect();
                found.push(format!("{day} {time}"));
                index = end;
                continue;
            }
        }
        index += 1;
    }
    found
}

fn detail_window(text: &str) -> (Option<String>, Option<String>) {
    let Some(at) = text.find("作业时间") else {
        return (None, None);
    };
    let window: String = text[at..].chars().take(160).collect();
    let mut found = stamps(&window).into_iter();
    (
        found.next().and_then(|value| beijing_stamp(&value)),
        found.next().and_then(|value| beijing_stamp(&value)),
    )
}

fn page_text(html: &str) -> String {
    use scraper::{Html, Selector};
    let document = Html::parse_document(html);
    let selector = Selector::parse("body").expect("static judge selector");
    let body = document.select(&selector).next();
    body.map(|body| body.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn collect(
    client: &reqwest::blocking::Client,
    lease: &mut RequestLease<'_>,
    service: &mut cas::ServiceSession,
    password: &str,
    requests: &mut usize,
) -> Result<(Vec<Value>, Value), Error> {
    let course_html = get_page(
        client,
        lease,
        service,
        &format!("{JUDGE_COURSE_LIST}0"),
        password,
    )?;
    *requests += 1;
    let course_links = courses(&course_html).len();
    let mut collected = Vec::new();
    let mut details_requested = 0usize;
    for (course_id, course_name) in courses(&course_html).into_iter().take(LIVE_COURSES) {
        get_page(
            client,
            lease,
            service,
            &format!("{JUDGE_COURSE_LIST}{course_id}"),
            password,
        )?;
        *requests += 1;
        let list_html = get_page(client, lease, service, JUDGE_ASSIGNMENT_LIST, password)?;
        *requests += 1;
        for (assignment_id, title) in assignments(&list_html) {
            let mut start = None;
            let mut due = None;
            if details_requested < LIVE_DETAILS {
                let detail = get_page(
                    client,
                    lease,
                    service,
                    &format!("{JUDGE_ASSIGNMENT_LIST}?assignID={assignment_id}"),
                    password,
                )?;
                *requests += 1;
                details_requested += 1;
                (start, due) = detail_window(&page_text(&detail));
            }
            collected.push(json!({
                "course_id": course_id,
                "course_name": course_name,
                "assignment_id": assignment_id,
                "title": title,
                "start": start,
                "due": due,
                "problems": []
            }));
        }
    }
    let counts = json!({
        "course_count": course_links,
        "assignment_count": collected.len(),
        "read_completed": true
    });
    Ok((collected, counts))
}

/// One explicit in-memory judge sign-on followed by the course list, one
/// assignment index per course and a bounded number of assignment details.
/// No submission, download or problem-content request is made.
pub fn session(input_text: &str, online: bool) -> Result<Value, Error> {
    if input_text.len() > 32 * 1024 {
        return Err(session_error(
            "invalid_input",
            "judge session input is invalid",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_str(input_text);
    let input: SessionInput = serde::Deserialize::deserialize(&mut deserializer)
        .map_err(|_| session_error("invalid_input", "judge session input is invalid"))?;
    deserializer
        .end()
        .map_err(|_| session_error("invalid_input", "judge session input is invalid"))?;
    if !input.authorized {
        return Err(session_error(
            "permission",
            "explicit authorization for one judge authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if input.intent != format!("LOGIN {} judge", input.username) {
        return Err(session_error(
            "invalid_input",
            "judge session input is invalid",
        ));
    }
    if !online {
        return Err(session_error(
            "online_required",
            "judge sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let client = cas::http_client()?;
    let governor = Governor::open()
        .map_err(|_| session_error("governor_error", "shared request admission unavailable"))?;
    let mut lease = net::acquire_kind(&governor, RequestKind::Authentication)?;
    let mut service =
        match cas::authenticate_service(&mut lease, &client, CasService::Judge, credentials) {
            Ok(service) => service,
            Err(failure) => {
                settle_auth(lease, &failure)?;
                return Err(failure);
            }
        };
    let mut requests = 0usize;
    let (collected, live_counts) = match collect(
        &client,
        &mut lease,
        &mut service,
        &input.password,
        &mut requests,
    ) {
        Ok(collected) => collected,
        Err(failure) => {
            let settled = match failure.code {
                "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
                "credential_echo" | "challenge_requires_human" => {
                    lease.finish(Outcome::CaptchaRequired)
                }
                _ => lease.finish_without_request(),
            };
            settled.map_err(|_| session_error("governor_error", "cannot settle judge session"))?;
            return Err(failure);
        }
    };
    lease
        .finish(Outcome::Http {
            status: 200,
            retry_after: None,
            challenge: false,
            network_failure: false,
        })
        .map_err(|_| session_error("governor_error", "cannot settle judge session"))?;
    let now = crate::civil_time::format_beijing(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0),
    );
    let projected = query(
        &json!({
            "now": now,
            "assignments": collected,
            "include_completed": false,
            "include_expired": false
        })
        .to_string(),
    );
    let mut output = projected;
    output["service"] = json!("judge");
    output["source"] = json!("network");
    output["network_performed"] = json!(true);
    output["submission_performed"] = json!(false);
    output["requests_performed"] = json!(requests);
    output["live_read"] = live_counts;
    output["credit"] = json!(CREDIT);
    let rendered = output.to_string();
    if service.contains_secret_bytes(rendered.as_bytes())
        || net::carries_secret(rendered.as_bytes(), &input.password)
    {
        return Err(session_error(
            "credential_echo",
            "the judge projection would echo credential material",
        ));
    }
    Ok(output)
}

pub fn schema() -> Value {
    json!({
        "stdin": "one JSON object of operator-supplied assignment records; this command performs no network request and no submission",
        "credit": CREDIT,
        "behavior": "https://github.com/BUAASubnet/UBAA/blob/3ac2ebd6c30162cd1ce1fc50964caa25ed22092f/docs/site/features/judge.md",
        "filter": "default keeps unfinished assignments whose due time is absent or not before now; include_expired adds expired assignments of every status without revealing future completed assignments",
        "failure": "read_error returns read_failed and suppresses the inventory; it is not an empty result"
    })
}

#[cfg(test)]
mod tests {
    use super::{assignments, courses, detail_window, query, session};
    use serde_json::json;

    fn assignment(
        course: &str,
        id: &str,
        title: &str,
        start: &str,
        due: &str,
        problems: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "course_id": course,
            "course_name": course,
            "assignment_id": id,
            "title": title,
            "start": start,
            "due": due,
            "problems": problems
        })
    }

    fn run(assignments: Vec<serde_json::Value>, extra: serde_json::Value) -> serde_json::Value {
        let mut input = json!({
            "now": "2026-11-22T09:00:00+08:00",
            "assignments": assignments
        });
        for (key, value) in extra.as_object().unwrap() {
            input[key] = value.clone();
        }
        query(&input.to_string())
    }

    #[test]
    fn default_view_groups_open_work_and_keeps_problem_order() {
        let partial = json!([
            {"name": "第二题", "score": null, "max_score": 20, "submitted": false},
            {"name": "第一题", "score": 10, "max_score": 10, "submitted": true}
        ]);
        let output = run(
            vec![
                assignment(
                    "算法",
                    "done",
                    "已完成",
                    "2026-11-01T08:00:00+08:00",
                    "2026-11-25T08:00:00+08:00",
                    json!([{"name":"A","score":1,"max_score":1,"submitted":true}]),
                ),
                assignment(
                    "算法",
                    "open",
                    "实验",
                    "2026-11-02T08:00:00+08:00",
                    "2026-11-30T08:00:00+08:00",
                    partial.clone(),
                ),
                assignment(
                    "数据结构",
                    "old",
                    "过期",
                    "2026-11-01T08:00:00+08:00",
                    "2026-11-21T08:00:00+08:00",
                    json!([{"name":"A","score":null,"max_score":1,"submitted":false}]),
                ),
            ],
            json!({}),
        );
        assert_eq!(output["result"], "projected");
        assert_eq!(output["network_performed"], false);
        assert_eq!(output["groups"].as_array().unwrap().len(), 1);
        let shown = &output["groups"][0]["assignments"];
        assert_eq!(shown.as_array().unwrap().len(), 1);
        assert_eq!(shown[0]["assignment_id"], "open");
        assert_eq!(shown[0]["status"], "partial");
        assert_eq!(shown[0]["status_text"], "部分提交");
        assert_eq!(shown[0]["submitted_count"], 1);
        assert_eq!(shown[0]["my_score"], 10);
        assert_eq!(shown[0]["max_score"], 30);
        let detail = run(
            vec![assignment(
                "算法",
                "open",
                "实验",
                "2026-11-02T08:00:00+08:00",
                "2026-11-30T08:00:00+08:00",
                partial,
            )],
            json!({"assignment_id":"open"}),
        );
        assert_eq!(detail["detail"]["problems"][0]["name"], "第二题");
        assert_eq!(detail["detail"]["problems"][1]["status"], "submitted");
    }

    #[test]
    fn expired_filter_does_not_reveal_future_completed_work() {
        let done = assignment(
            "算法",
            "done",
            "已完成",
            "2026-11-01T08:00:00+08:00",
            "2026-11-25T08:00:00+08:00",
            json!([{"name":"A","score":1,"max_score":1,"submitted":true}]),
        );
        let old = assignment(
            "算法",
            "old",
            "过期完成",
            "2026-11-01T08:00:00+08:00",
            "2026-11-20T08:00:00+08:00",
            json!([{"name":"A","score":1,"max_score":1,"submitted":true}]),
        );
        let output = run(vec![done, old], json!({"include_expired": true}));
        let ids: Vec<_> = output["groups"][0]["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["assignment_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["old"]);
    }

    #[test]
    fn sort_search_and_exact_due_follow_the_requested_view() {
        let later = assignment(
            "数据结构",
            "later",
            "后一个",
            "2026-11-03T08:00:00+08:00",
            "2026-11-29T08:00:00+08:00",
            json!([]),
        );
        let earlier = assignment(
            "算法",
            "earlier",
            "前一个",
            "2026-11-09T08:00:00+08:00",
            "2026-11-24T08:00:00+08:00",
            json!([]),
        );
        let due_now = assignment(
            "算法",
            "now",
            "刚好截止",
            "2026-11-09T08:00:00+08:00",
            "2026-11-22T09:00:00+08:00",
            json!([]),
        );
        let output = run(
            vec![later, earlier.clone(), due_now],
            json!({"sort":"start","order":"desc","query":"算法"}),
        );
        let ids: Vec<_> = output["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["assignments"].as_array().unwrap())
            .map(|value| value["assignment_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(ids, vec!["now", "earlier"]);
        assert_eq!(output["groups"][0]["course_id"], "算法");
        assert!(
            query(
                &json!({"now":"2026-11-22T09:00:00+08:00","assignments":[earlier, earlier]})
                    .to_string()
            )["error"]
                .is_string()
        );
    }

    #[test]
    fn read_failure_suppresses_inventory_text() {
        let output = run(
            vec![assignment(
                "算法",
                "secret-id",
                "机密作业标题",
                "2026-11-01T08:00:00+08:00",
                "2026-11-30T08:00:00+08:00",
                json!([]),
            )],
            json!({"read_error":"upstream closed"}),
        );
        assert_eq!(output["result"], "read_failed");
        assert!(output["groups"].is_null());
        assert!(!output.to_string().contains("机密作业标题"));
        assert!(!output.to_string().contains("secret-id"));
        assert_eq!(output["credit"], super::CREDIT);
    }

    #[test]
    fn course_and_assignment_links_keep_their_identifiers() {
        let list = r#"<html><a href="courselist.jsp?courseID=0">全部</a>
            <a href="courselist.jsp?courseID=12">编译技术</a>
            <a href="courselist.jsp?courseID=12">重复</a>
            <a href="courselist.jsp?courseID=9">体系结构</a></html>"#;
        assert_eq!(
            courses(list),
            vec![
                ("12".to_owned(), "编译技术".to_owned()),
                ("9".to_owned(), "体系结构".to_owned())
            ]
        );
        let page = r#"<html><a href="index.jsp?assignID=101">实验一</a>
            <a href="index.jsp?assignID=101">重复</a>
            <a href="index.jsp?assignID=202&amp;problemContent=1">题面</a>
            <a href="judgeDetails.jsp?assignID=303">详情</a></html>"#;
        assert_eq!(
            assignments(page),
            vec![("101".to_owned(), "实验一".to_owned())]
        );
    }

    #[test]
    fn detail_window_reads_both_beijing_stamps() {
        let text = "作业时间：2026-04-20 09:00:00 至 2026-05-03 23:59 作业满分：5，共 1道 题";
        assert_eq!(
            detail_window(text),
            (
                Some("2026-04-20T09:00:00+08:00".to_owned()),
                Some("2026-05-03T23:59:00+08:00".to_owned())
            )
        );
    }

    #[test]
    fn session_without_online_does_not_authenticate() {
        let error = session(
            r#"{"authorized":true,"username":"student","password":"secret","intent":"LOGIN student judge"}"#,
            false,
        )
        .expect_err("offline session must refuse");
        assert_eq!(error.code, "online_required");
    }
}

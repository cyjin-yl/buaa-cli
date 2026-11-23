//! Local projection of operator-supplied personal income records.
//!
//! Year selection, search, totals, and month grouping follow the behavior
//! described by BUAASubnet/UBAA `docs/site/features/finance.md` at
//! `3ac2ebd6c30162cd1ce1fc50964caa25ed22092f` (MIT, © 2026 MooreFoss). This is
//! original code. It does not contact the campus finance service, does not
//! accept bank or identity material, and does not treat a failed refresh as an
//! empty income history. Amounts are integer cents and are not reconciled to a
//! bank settlement.

use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;

use crate::civil_time::parse_date;
use crate::{
    governor::{FollowupError, Governor, Outcome, RequestKind, RequestLease},
    net::{self, Error},
    recordings::session::{self as cas, CasService, SsoCredentials},
    timetable::admit_session_read,
};

const FINANCE_PORTAL_URL: &str = "https://icw.buaa.edu.cn/Newindex.aspx";
const FINANCE_JUMP_URL: &str = "https://icw.buaa.edu.cn/jump.aspx?sysid=wscx";
const FINANCE_QUERY_HOST: &str = "chaxun.icw.buaa.edu.cn";
const FINANCE_LOGIN_URL: &str = "https://chaxun.icw.buaa.edu.cn/api-zhcx/login";
const FINANCE_INCOME_URL: &str = "https://chaxun.icw.buaa.edu.cn/api-zhcx/getStudentSRCX";
const FINANCE_LOGIN_PATH: &str = "/gxzhcxzhb/login";
const FINANCE_PAGE_SIZE: u64 = 100;
const FINANCE_MAX_PAGES: u32 = 20;
const FINANCE_BODY_LIMIT: u64 = 512 * 1024;
const FINANCE_CREDENTIAL_LIMIT: usize = 4096;

const CREDIT: &str =
    "BUAASubnet/UBAA@3ac2ebd6c30162cd1ce1fc50964caa25ed22092f (MIT, © 2026 MooreFoss)";
const MAX_RECORDS: usize = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    year: Option<i32>,
    query: Option<String>,
    refresh_error: Option<String>,
    records: Vec<Record>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    serial: String,
    project: String,
    summary: String,
    gross_cents: Option<i64>,
    tax_cents: Option<i64>,
    net_cents: Option<i64>,
    tax_rate: Option<String>,
    year: i32,
    month: u8,
    recorded_on: String,
}

pub fn query(input: &str) -> Value {
    let parsed = match serde_json::from_str::<Query>(input) {
        Ok(value) => value,
        Err(_) => return invalid("input must be one finance JSON object"),
    };
    match project(parsed) {
        Ok(value) => value,
        Err(message) => invalid(message),
    }
}

fn project(query: Query) -> Result<Value, &'static str> {
    if let Some(year) = query.year
        && !(1970..=2100).contains(&year)
    {
        return Err("year is outside the supported range");
    }
    if let Some(search) = query.query.as_deref()
        && (search.is_empty() || search.chars().count() > 100)
    {
        return Err("query must be a non-empty search of at most 100 characters");
    }
    let refresh_error = match query.refresh_error.as_deref() {
        Some("") => return Err("refresh_error must be a short non-empty reason"),
        Some(error) if error.chars().count() > 300 => {
            return Err("refresh_error must be a short non-empty reason");
        }
        other => other,
    };
    if query.records.len() > MAX_RECORDS {
        return Err("too many income records");
    }
    let mut records = Vec::with_capacity(query.records.len());
    let mut serials = std::collections::BTreeSet::new();
    for record in query.records {
        validate(&record)?;
        if !serials.insert(record.serial.clone()) {
            return Err("serial must be unique");
        }
        records.push(record);
    }
    if refresh_error.is_some() && records.is_empty() {
        return Ok(json!({
            "result": "refresh_failed",
            "record_state": "offline_retained",
            "refresh_error": refresh_error,
            "empty_means_no_income": false,
            "bank_settlement_known": false,
            "coverage": "supplied_records_only",
            "network_performed": false,
            "totals": null,
            "months": [],
            "credit": CREDIT
        }));
    }
    records.retain(|record| {
        query.year.is_none_or(|year| record.year == year)
            && query.query.as_ref().is_none_or(|search| {
                record.project.contains(search) || record.summary.contains(search)
            })
    });
    records.sort_by(|left, right| {
        (left.recorded_on.as_str(), left.serial.as_str())
            .cmp(&(right.recorded_on.as_str(), right.serial.as_str()))
    });
    let totals = totals(&records);
    let mut months: BTreeMap<(i32, u8), Vec<&Record>> = BTreeMap::new();
    for record in &records {
        months
            .entry((record.year, record.month))
            .or_default()
            .push(record);
    }
    let months = months
        .into_iter()
        .map(|((year, month), entries)| {
            json!({
                "year": year,
                "month": month,
                "net_cents": sum(entries.iter().map(|record| record.net_cents)),
                "count": entries.len(),
                "records": entries.iter().map(|record| detail(record)).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "result": "projected",
        "record_state": if refresh_error.is_some() { "offline_retained" } else { "supplied" },
        "refresh_error": refresh_error,
        "empty_means_no_income": false,
        "bank_settlement_known": false,
        "coverage": "supplied_records_only",
        "network_performed": false,
        "totals": totals,
        "months": months,
        "credit": CREDIT
    }))
}

fn validate(record: &Record) -> Result<(), &'static str> {
    if record.serial.is_empty() || record.serial.chars().count() > 64 {
        return Err("serial must be 1 to 64 characters");
    }
    if record.project.is_empty()
        || record.summary.is_empty()
        || record.project.chars().count() > 200
        || record.summary.chars().count() > 200
    {
        return Err("project and summary must be 1 to 200 characters");
    }
    for amount in [record.gross_cents, record.tax_cents, record.net_cents] {
        if amount.is_some_and(|amount| amount < 0) {
            return Err("amounts must be zero or positive cents");
        }
    }
    if let Some(rate) = record.tax_rate.as_deref()
        && !valid_rate(rate)
    {
        return Err("tax_rate must be a percentage from 0 to 100 with at most two decimals");
    }
    if !(1970..=2100).contains(&record.year) || !(1..=12).contains(&record.month) {
        return Err("record month is outside the supported range");
    }
    if parse_date(&record.recorded_on).is_none() {
        return Err("recorded_on must be a civil date");
    }
    Ok(())
}

fn valid_rate(value: &str) -> bool {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    if whole.is_empty()
        || whole.len() > 3
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || fraction.len() > 2
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }
    let whole: u16 = whole.parse().unwrap_or(101);
    let fraction: u16 = fraction.unwrap_or("0").parse().unwrap_or(100);
    whole < 100 || (whole == 100 && fraction == 0)
}

fn totals(records: &[Record]) -> Value {
    json!({
        "count": records.len(),
        "gross_cents": sum(records.iter().map(|record| record.gross_cents)),
        "tax_cents": sum(records.iter().map(|record| record.tax_cents)),
        "net_cents": sum(records.iter().map(|record| record.net_cents))
    })
}

fn sum(values: impl Iterator<Item = Option<i64>>) -> Option<i64> {
    let mut total = 0;
    for value in values {
        total += value?;
    }
    Some(total)
}

fn detail(record: &Record) -> Value {
    let consistent = match (record.gross_cents, record.tax_cents, record.net_cents) {
        (Some(gross), Some(tax), Some(net)) => Some(net == gross - tax),
        _ => None,
    };
    json!({
        "serial": record.serial,
        "project": record.project,
        "summary": record.summary,
        "gross_cents": record.gross_cents,
        "tax_cents": record.tax_cents,
        "net_cents": record.net_cents,
        "amount_consistent": consistent,
        "tax_rate": record.tax_rate,
        "year": record.year,
        "month": record.month,
        "recorded_on": record.recorded_on
    })
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

/// Settle one attempt that already started. Every early return after the
/// sign-on reaches this, so the governor never keeps a pending attempt.
fn settle(lease: RequestLease<'_>, failure: &Error) -> Result<(), Error> {
    if matches!(
        failure.code,
        "governor_error" | "governor_denied" | "governor_unavailable"
    ) {
        drop(lease);
        return Ok(());
    }
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
    settled.map_err(|_| session_error("governor_error", "cannot settle finance attempt"))
}

/// One explicit CAS sign-on to the finance portal, one portal jump and, only
/// when the deployment serves the query service, the query-service login and
/// the bounded income pages. The jump target is consumed in memory and never
/// fetched, and no response body is exported.
pub fn session(input_text: &str, online: bool) -> Result<Value, Error> {
    if input_text.len() > 32 * 1024 {
        return Err(session_error("invalid_input", "finance session input is invalid"));
    }
    let mut deserializer = serde_json::Deserializer::from_str(input_text);
    let input: SessionInput = serde::Deserialize::deserialize(&mut deserializer)
        .map_err(|_| session_error("invalid_input", "finance session input is invalid"))?;
    deserializer
        .end()
        .map_err(|_| session_error("invalid_input", "finance session input is invalid"))?;
    if !input.authorized {
        return Err(session_error(
            "permission",
            "explicit authorization for one finance authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if input.intent != format!("LOGIN {} finance", input.username) {
        return Err(session_error("invalid_input", "finance session input is invalid"));
    }
    if !online {
        return Err(session_error(
            "online_required",
            "finance sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let client = cas::http_client()?;
    let governor = Governor::open()
        .map_err(|_| session_error("governor_error", "shared request admission unavailable"))?;
    let mut lease = net::acquire_kind(&governor, RequestKind::Authentication)?;
    let mut service =
        match cas::authenticate_service(&mut lease, &client, CasService::Finance, credentials) {
            Ok(service) => service,
            Err(failure) => {
                settle(lease, &failure)?;
                return Err(failure);
            }
        };
    let mut requests = 0usize;
    let (read, secrets) = match read_income(&client, &mut lease, &mut service, &mut requests) {
        Ok(read) => read,
        Err(failure) => {
            settle(lease, &failure)?;
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
        .map_err(|_| session_error("governor_error", "cannot settle finance session"))?;
    if read["state"] == "service_unavailable" {
        let mut output = read.clone();
        output["service"] = json!("icw");
        output["source"] = json!("network");
        output["network_performed"] = json!(true);
        output["requests_performed"] = json!(requests);
        output["read_completed"] = json!(false);
        output["record_state"] = json!("no_records_read");
        output["bank_settlement_known"] = json!(false);
        output["credit"] = json!(CREDIT);
        return Ok(output);
    }
    let records = read["records"].clone();
    let pages = read["pages"].clone();
    let projected = query(&json!({ "records": records }).to_string());
    if projected.get("error").is_some() {
        return Err(session_error(
            "upstream_parse",
            "the finance records do not satisfy the local projection contract",
        ));
    }
    let mut output = projected;
    output["service"] = json!("icw");
    output["source"] = json!("network");
    output["network_performed"] = json!(true);
    output["requests_performed"] = json!(requests);
    output["pages_read"] = json!(pages);
    output["bank_settlement_known"] = json!(false);
    output["credit"] = json!(CREDIT);
    let rendered = output.to_string();
    if service.contains_secret_bytes(rendered.as_bytes())
        || net::carries_secret(rendered.as_bytes(), &input.password)
        || secrets
            .iter()
            .any(|secret| net::carries_secret(rendered.as_bytes(), secret.as_str()))
    {
        return Err(session_error(
            "credential_echo",
            "the finance projection would echo credential material",
        ));
    }
    Ok(output)
}

/// The portal jump, the query-service login and the income pages.
fn read_income(
    client: &reqwest::blocking::Client,
    lease: &mut RequestLease<'_>,
    service: &mut cas::ServiceSession,
    requests: &mut usize,
) -> Result<(Value, Vec<zeroize::Zeroizing<String>>), Error> {
    let jump_url = url::Url::parse(FINANCE_JUMP_URL)
        .map_err(|_| session_error("invalid_input", "finance session input is invalid"))?;
    let (cookie, expiry) = service.cookie_header_for_transmission(&jump_url)?;
    if let Err(failure) = admit_session_read(lease) {
        return Err(failure);
    }
    if expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
        return Err(session_error(
            "scoped_cookie_unusable",
            "the finance cookie expired before the jump; no request was sent",
        ));
    }
    let mut builder = client
        .get(FINANCE_JUMP_URL)
        .header("Accept", "text/html")
        .header("Referer", FINANCE_PORTAL_URL)
        .timeout(std::time::Duration::from_secs(45))
        .header("Accept-Encoding", "identity");
    if let Some(cookie) = cookie {
        builder = builder.header("Cookie", cookie);
    }
    let mut request = builder
        .build()
        .map_err(|_| session_error("invalid_input", "finance request is not admissible"))?;
    if let Some(value) = request.headers_mut().get_mut("cookie") {
        value.set_sensitive(true);
    }
    let response = match lease.start_request(|| Some(client.execute(request))) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) | Ok(None) => {
            return Err(session_error(
                "network_error",
                "finance portal jump failed; no automatic retry",
            ));
        }
        Err(FollowupError::Governor(_)) => {
            return Err(session_error(
                "governor_error",
                "request safety admission failed; pending outcome retained",
            ));
        }
    };
    *requests += 1;
    let status = response.status().as_u16();
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
            "cannot persist finance response",
        ));
    }
    if challenge {
        return Err(session_error("challenge_requires_human", "finance jump requires review"));
    }
    if status != 302 {
        return Err(session_error(
            "authentication_unconfirmed",
            "finance portal jump was refused",
        ));
    }
    let location = zeroize::Zeroizing::new(
        response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| {
            session_error(
                "authentication_unconfirmed",
                "finance portal jump carried no query-service target",
            )
        })?,
    );
    // The jump target carries credential material in its query. Split it
    // first so no credential-bearing URL object is ever built, and only the
    // zeroized buffer holds the raw value.
    let (base, query) = match location.split_once('?') {
        Some((base, query)) => (base, query),
        None => (location.as_str(), ""),
    };
    let target = url::Url::parse(base)
        .map_err(|_| session_error("upstream_parse", "finance jump target is not a URL"))?;
    if target.scheme() != "https"
        || target.host_str() != Some(FINANCE_QUERY_HOST)
        || target.path() != FINANCE_LOGIN_PATH
    {
        // The deployment answers with another origin. Report the observed
        // host and path only: the target's query carries credential material
        // and is never exported.
        return Ok((
            json!({
                "state": "service_unavailable",
                "observed_target": {
                    "host": target.host_str().unwrap_or(""),
                    "path": target.path()
                },
                "http_status": status
            }),
            Vec::new(),
        ));
    }
    let mut user = None;
    let mut secret = None;
    let mut stamp = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let slot = match name.as_ref() {
            "Userid" => &mut user,
            "Cypt" => &mut secret,
            "Stamp" => &mut stamp,
            _ => continue,
        };
        if slot.is_some() || value.is_empty() || value.len() > FINANCE_CREDENTIAL_LIMIT {
            return Err(session_error(
                "upstream_parse",
                "finance jump target carried an unusable credential parameter",
            ));
        }
        *slot = Some(value.into_owned());
    }
    let (Some(user), Some(secret), Some(stamp)) = (user, secret, stamp) else {
        return Err(session_error(
            "upstream_parse",
            "finance jump target carried an incomplete credential set",
        ));
    };
    let user = zeroize::Zeroizing::new(user);
    let secret = zeroize::Zeroizing::new(secret);
    let stamp = zeroize::Zeroizing::new(stamp);
    let referer = location.as_str();
    if let Err(failure) = admit_session_read(lease) {
        return Err(failure);
    }
    let mut login = client
        .post(FINANCE_LOGIN_URL)
        .form(&[
            ("username", user.as_str()),
            ("password", secret.as_str()),
            ("yzm", "yzm"),
            ("stamp", stamp.as_str()),
        ])
        .header("Referer", referer)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(45))
        .header("Accept-Encoding", "identity")
        .build()
        .map_err(|_| session_error("invalid_input", "finance request is not admissible"))?;
    if let Some(value) = login.headers_mut().get_mut("referer") {
        value.set_sensitive(true);
    }
    let response = match lease.start_request(|| Some(client.execute(login))) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) | Ok(None) => {
            return Err(session_error(
                "network_error",
                "finance query-service login failed; no automatic retry",
            ));
        }
        Err(FollowupError::Governor(_)) => {
            return Err(session_error(
                "governor_error",
                "request safety admission failed; pending outcome retained",
            ));
        }
    };
    *requests += 1;
    let body = read_json_body(client_response_body(response)?)?;
    let token = envelope_token(&body)?;
    let token = zeroize::Zeroizing::new(token);
    let mut records = Vec::new();
    let mut pages = 0u32;
    let mut expected_total: Option<usize> = None;
    for page in 1..=FINANCE_MAX_PAGES {
        if let Err(failure) = admit_session_read(lease) {
            return Err(failure);
        }
        let mut income = client
            .post(FINANCE_INCOME_URL)
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(45))
            .header("Accept-Encoding", "identity")
            .body(
                json!({"userId": user.as_str(), "currentPage": page, "limit": FINANCE_PAGE_SIZE})
                    .to_string(),
            )
            .build()
            .map_err(|_| session_error("invalid_input", "finance request is not admissible"))?;
        if let Some(value) = income.headers_mut().get_mut("authorization") {
            value.set_sensitive(true);
        }
        let response = match lease.start_request(|| Some(client.execute(income))) {
            Ok(Some(Ok(response))) => response,
            Ok(Some(Err(_))) | Ok(None) => {
                return Err(session_error(
                    "network_error",
                    "finance income read failed; no automatic retry",
                ));
            }
            Err(FollowupError::Governor(_)) => {
                return Err(session_error(
                    "governor_error",
                    "request safety admission failed; pending outcome retained",
                ));
            }
        };
        *requests += 1;
        let body = read_json_body(client_response_body(response)?)?;
        let (rows, total) = income_page(&body)?;
        if expected_total.is_some_and(|previous| previous != total) {
            return Err(session_error(
                "upstream_parse",
                "finance income pagination changed between pages",
            ));
        }
        expected_total = Some(total);
        pages += 1;
        let empty = rows.is_empty();
        for row in rows {
            records.push(income_record(&row)?);
        }
        if records.len() == total {
            break;
        }
        if empty || records.len() > total {
            return Err(session_error(
                "upstream_parse",
                "finance income pagination is incomplete",
            ));
        }
    }
    if expected_total.is_some_and(|total| records.len() != total) {
        return Err(session_error(
            "upstream_parse",
            "finance income pagination is incomplete",
        ));
    }
    // The values stay alive, and zeroized on drop, so the caller can screen
    // the exported projection against them.
    let secrets = vec![user, secret, stamp, token];
    Ok((json!({"state": "records", "records": records, "pages": pages}), secrets))
}

fn client_response_body(response: reqwest::blocking::Response) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    response
        .take(FINANCE_BODY_LIMIT)
        .read_to_end(&mut body)
        .map_err(|_| session_error("network_error", "finance body read failed"))?;
    Ok(body)
}

fn read_json_body(body: Vec<u8>) -> Result<Value, Error> {
    serde_json::from_slice(&body).map_err(|_| {
        session_error(
            "upstream_parse",
            "finance response was not the reviewed JSON",
        )
    })
}

fn envelope_token(body: &Value) -> Result<String, Error> {
    match body.get("code").and_then(Value::as_i64) {
        Some(200) => {}
        Some(401) => {
            return Err(session_error(
                "auth_latched",
                "the finance query service rejected the session",
            ));
        }
        _ => {
            return Err(session_error(
                "upstream_parse",
                "finance response did not report success",
            ));
        }
    }
    let data = body
        .get("data")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            session_error("upstream_parse", "finance response carried no data object")
        })?;
    data.get("token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            session_error("upstream_parse", "finance response carried no session token")
        })
}

fn income_page(body: &Value) -> Result<(Vec<Value>, usize), Error> {
    if body.get("code").and_then(Value::as_i64) != Some(200) {
        return Err(session_error(
            "upstream_parse",
            "finance income response did not report success",
        ));
    }
    let data = body
        .get("data")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income response carried no data object")
        })?;
    let (rows_key, total_key) = if data.get("mx").is_some() || data.get("total").is_some() {
        ("mx", "total")
    } else {
        ("data", "count")
    };
    let rows = data
        .get(rows_key)
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income response carried no rows")
        })?;
    let total = data
        .get(total_key)
        .and_then(Value::as_u64)
        .and_then(|total| usize::try_from(total).ok())
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income response carried no total")
        })?;
    if rows.len() > total {
        return Err(session_error(
            "upstream_parse",
            "finance income response carried more rows than its total",
        ));
    }
    Ok((rows, total))
}

fn amount_cents(value: &Value) -> Result<Option<i64>, Error> {
    if value.is_null() {
        return Ok(None);
    }
    let number = value
        .as_number()
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income amount was not a number")
        })?
        .to_string();
    let (negative, text) = number
        .strip_prefix('-')
        .map_or((false, number.as_str()), |value| (true, value));
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 2
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(session_error(
            "upstream_parse",
            "finance income amount was not a decimal amount",
        ));
    }
    let whole = whole.parse::<i64>().map_err(|_| {
        session_error("upstream_parse", "finance income amount was out of range")
    })?;
    let fraction = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<i64>().map_err(|_| {
            session_error("upstream_parse", "finance income amount was not a decimal amount")
        })? * 10,
        _ => fraction.parse::<i64>().map_err(|_| {
            session_error("upstream_parse", "finance income amount was not a decimal amount")
        })?,
    };
    let cents = whole
        .checked_mul(100)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income amount was out of range")
        })?;
    Ok(Some(if negative { -cents } else { cents }))
}

fn income_record(row: &Value) -> Result<Value, Error> {
    let serial = row
        .get("lsh")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income row carried no serial")
        })?
        .to_owned();
    let project = row
        .get("ffxmmc")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("未提供项目")
        .to_owned();
    let summary = row
        .get("zy")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("未提供摘要")
        .to_owned();
    let tax_rate = row
        .get("slbfb")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let recorded_on = row
        .get("lrrq")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income row carried no recorded date")
        })?
        .to_owned();
    let year = row
        .get("nian")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income row carried no year")
        })?;
    let month = row
        .get("yue")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
        .ok_or_else(|| {
            session_error("upstream_parse", "finance income row carried no month")
        })?;
    Ok(json!({
        "serial": serial,
        "project": project,
        "summary": summary,
        "gross_cents": amount_cents(&row["je"])?,
        "tax_cents": amount_cents(&row["se"])?,
        "net_cents": amount_cents(&row["sfje"])?,
        "tax_rate": tax_rate,
        "year": year,
        "month": month,
        "recorded_on": recorded_on
    }))
}

pub fn schema() -> Value {
    json!({
        "stdin": "one JSON object of operator-supplied income records in integer cents; no bank account, identity, or network request is accepted",
        "credit": CREDIT,
        "behavior": "https://github.com/BUAASubnet/UBAA/blob/3ac2ebd6c30162cd1ce1fc50964caa25ed22092f/docs/site/features/finance.md",
        "totals": "count, gross, tax, and net follow the selected year and search; a missing component makes only that total null",
        "failure": "refresh_error retains supplied records as offline_retained; with no retained records the result is refresh_failed and does not mean there was no income"
    })
}

#[cfg(test)]
mod tests {
    use super::{query, session};
    use serde_json::{Value, json};

    fn record(
        serial: &str,
        project: &str,
        summary: &str,
        gross: i64,
        tax: i64,
        net: i64,
        month: u8,
    ) -> serde_json::Value {
        json!({
            "serial": serial,
            "project": project,
            "summary": summary,
            "gross_cents": gross,
            "tax_cents": tax,
            "net_cents": net,
            "tax_rate": "3.00",
            "year": 2026,
            "month": month,
            "recorded_on": format!("2026-{month:02}-15")
        })
    }

    #[test]
    fn search_changes_totals_and_preserves_inconsistent_amounts() {
        let mut mismatched = record("S2", "助学金", "十一月", 100_000, 3_000, 100_000, 11);
        mismatched["recorded_on"] = json!("2026-12-02");
        let output = query(
            &json!({
                "year": 2026,
                "query": "助学",
                "records": [
                    record("S1", "酬金", "监考", 50_000, 5_000, 45_000, 11),
                    mismatched,
                    record("S3", "助学金", "十二月", 80_000, 0, 80_000, 12)
                ]
            })
            .to_string(),
        );
        assert_eq!(output["totals"]["count"], 2);
        assert_eq!(output["totals"]["net_cents"], 180_000);
        assert_eq!(output["months"][0]["month"], 11);
        assert_eq!(
            output["months"][0]["records"][0]["amount_consistent"],
            false
        );
        assert_eq!(output["months"][0]["records"][0]["net_cents"], 100_000);
        assert_eq!(
            output["months"][0]["records"][0]["recorded_on"],
            "2026-12-02"
        );
        assert_eq!(output["months"][1]["net_cents"], 80_000);
        assert_eq!(output["bank_settlement_known"], false);
    }

    #[test]
    fn missing_tax_nulls_only_that_total_and_failed_refresh_is_not_zero() {
        let mut partial = record("S1", "酬金", "监考", 50_000, 0, 50_000, 11);
        partial["tax_cents"] = Value::Null;
        let output = query(&json!({"records":[partial]}).to_string());
        assert_eq!(output["totals"]["count"], 1);
        assert_eq!(output["totals"]["gross_cents"], 50_000);
        assert!(output["totals"]["tax_cents"].is_null());
        let failed = query(&json!({"refresh_error":"timeout","records":[]}).to_string());
        assert_eq!(failed["result"], "refresh_failed");
        assert_eq!(failed["empty_means_no_income"], false);
        assert!(failed["totals"].is_null());
        let retained = query(
            &json!({
                "refresh_error":"timeout",
                "records":[record("S1", "酬金", "监考", 50_000, 0, 50_000, 11)]
            })
            .to_string(),
        );
        assert_eq!(retained["record_state"], "offline_retained");
        assert_eq!(retained["months"][0]["count"], 1);
    }

    #[test]
    fn rejects_negative_duplicate_and_implausible_rate_without_echo() {
        let duplicate = query(
            &json!({"records":[
                record("SAME", "酬金", "甲", 1, 0, 1, 11),
                record("SAME", "酬金", "乙", 1, 0, 1, 11)
            ]})
            .to_string(),
        );
        assert_eq!(duplicate["error"], "invalid_input");
        assert!(!duplicate.to_string().contains("SAME"));
        let negative = record("S1", "酬金", "甲", 1, -1, 1, 11);
        assert_eq!(
            query(&json!({"records":[negative]}).to_string())["error"],
            "invalid_input"
        );
        let mut rate = record("S1", "酬金", "甲", 1, 0, 1, 11);
        rate["tax_rate"] = json!("100.01");
        assert_eq!(
            query(&json!({"records":[rate]}).to_string())["error"],
            "invalid_input"
        );
    }

    #[test]
    fn session_without_online_does_not_authenticate() {
        let error = session(
            r#"{"authorized":true,"username":"student","password":"secret","intent":"LOGIN student finance"}"#,
            false,
        )
        .expect_err("offline session must refuse");
        assert_eq!(error.code, "online_required");
    }
}

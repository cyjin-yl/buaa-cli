//! Graduate marks session: one explicit in-memory CAS login to GSMIS, one
//! `wdcjapp` application document and up to three `xscjcx.do` pages. Secrets
//! are stdin-only inputs; they are never persisted, logged or placed inside a
//! generic Value tree. The read performs no writes, retries or refreshes.
//! Session cookies issued by the application and read responses
//! are absorbed into the same invocation-only jar and screened like every
//! other credential, never exported or persisted.
//!
//! The response contract projects `datas.xscjcx.rows` verbatim after the
//! credential/challenge screens; rows are never synthesized and an incomplete
//! page stays `complete: false`. When `xnxqdm` is supplied only rows whose
//! XNXQDM equals the requested term are projected; other-term rows are
//! counted, never emitted.

use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::Cell;
use std::hash::{BuildHasher, RandomState};
use std::io::Read;
use std::sync::LazyLock;
use zeroize::Zeroizing;

use crate::{
    governor::{Governor, Outcome, RequestKind, RequestLease},
    net::{self, Error},
    recordings::session::{self as cas, CasService, SsoCredentials},
    timetable::{
        self, BodyScreening, ReadScreening, SESSION_BODY_LIMIT, admit_read_body,
        admit_session_read, decoded_body_screening, deserialize_object, deserialize_secret,
        receive_context_response, screen_context_response, session_request, valid_term_code,
        with_provenance,
    },
};

const SESSION_MAX_INPUT: usize = 65536;
/// Every request retains this size so pageNumber keeps the same source offset.
const READ_PAGE_SIZE: usize = 200;
const MAX_PAGES: usize = 3;
/// Bound source rows before term filtering across the whole invocation.
const MAX_ROWS: usize = 512;
static PAGE_HASH: LazyLock<RandomState> = LazyLock::new(RandomState::new);
const MARKS_PAGE_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdcjapp/*default/index.do";
const MARKS_PORTAL_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do";
const MARKS_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdcjapp/modules/wdcj/xscjcx.do";
const MARKS_REFERER: &str = MARKS_PAGE_URL;
const SCOPE: &str = "up to three HTTPS datas.xscjcx pages and 512 source rows; fixed pageSize=200 preserves pageNumber offsets; rows are projected in source order without deduplication, synthesis or field review; declared_total/declared_page_size retain first-page facts and page_facts report each admitted envelope; requested-xnxqdm filtering counts non-matching rows without emitting them";

fn error(code: &'static str, message: &'static str) -> Error {
    Error::new(code, message)
}

fn session_invalid() -> Error {
    error(
        "invalid_input",
        "marks session input does not match the xscjcx contract",
    )
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
    /// Optional requested term filter: exactly the five-digit XNXQDM shape
    /// the terminal parser admits (four digits plus 1, 2 or 3). Omitted
    /// admits every returned row; present filters server-side facts
    /// client-side and never narrows the source collection.
    xnxqdm: Option<String>,
}

impl<'de> Deserialize<'de> for SessionRead {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum Raw {
            Xscjcx {
                enabled: bool,
                #[serde(default)]
                xnxqdm: Option<String>,
            },
        }
        let (enabled, xnxqdm) = match deserialize_object(deserializer)? {
            Raw::Xscjcx { enabled, xnxqdm } => (enabled, xnxqdm),
        };
        Ok(Self { enabled, xnxqdm })
    }
}

/// Strict private JSON parse: duplicate members are refused rather than
/// silently projected, and the value is wiped when dropped. Envelope facts
/// are read off this value; projected rows clone out of it.
fn strict_value(bytes: &[u8]) -> Result<timetable::PrivateValue, Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = timetable::PrivateValue::deserialize(&mut de)
        .map_err(|_| error("upstream_parse", "marks response is not strict JSON"))?;
    de.end()
        .map_err(|_| error("upstream_parse", "marks response has trailing content"))?;
    Ok(value)
}

/// Project one admitted xscjcx body. Every structural failure is a labeled
/// fallback, never a fabricated grade row; rows keep their upstream fields.
fn parse_marks_page(
    body: &str,
    requested_term: Option<&str>,
    row_fingerprint: &Cell<Option<u64>>,
) -> Value {
    let value = match strict_value(body.as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            return json!({
                "schema_version": 1,
                "type": "marks_gsmis",
                "result": "fallback",
                "fallback_reason": "invalid_json",
            });
        }
    };
    let envelope = &value.0;
    let Some(code) = envelope.get("code").and_then(Value::as_str) else {
        return json!({
            "schema_version": 1,
            "type": "marks_gsmis",
            "result": "fallback",
            "fallback_reason": "unrecognized_envelope",
        });
    };
    if code != "0" {
        return json!({
            "schema_version": 1,
            "type": "marks_gsmis",
            "result": "business_error",
            "upstream_code": code,
            "upstream_message": envelope
                .get("msg")
                .or_else(|| envelope.get("message"))
                .cloned()
                .unwrap_or(Value::Null),
        });
    }
    let section = match envelope.get("datas").and_then(|d| d.get("xscjcx")) {
        Some(section) if section.is_object() => section,
        _ => {
            return json!({
                "schema_version": 1,
                "type": "marks_gsmis",
                "result": "fallback",
                "fallback_reason": "unrecognized_data_shape",
            });
        }
    };
    let rows = match section.get("rows").and_then(Value::as_array) {
        Some(rows) => rows,
        None => {
            return json!({
                "schema_version": 1,
                "type": "marks_gsmis",
                "result": "fallback",
                "fallback_reason": "unrecognized_data_shape",
            });
        }
    };
    if rows.len() > MAX_ROWS {
        return json!({
            "schema_version": 1,
            "type": "marks_gsmis",
            "result": "fallback",
            "fallback_reason": "row_count_exceeds_bound",
            "source_row_count": rows.len(),
            "declared_total": section.get("totalSize").and_then(Value::as_u64),
            "declared_page_size": section.get("pageSize").and_then(Value::as_u64),
        });
    }
    let total_size = section.get("totalSize").and_then(Value::as_u64);
    let page_size = section.get("pageSize").and_then(Value::as_u64);
    // Compare full source pages before filtering, without retaining copies of
    // excluded rows. A match makes completeness uncertain.
    row_fingerprint.set(Some(PAGE_HASH.hash_one(rows)));
    let mut matched = Vec::new();
    let mut other_term = 0usize;
    let mut unscoped_term = 0usize;
    for row in rows {
        let term = row.get("XNXQDM").and_then(Value::as_str);
        match (requested_term, term) {
            (Some(want), Some(have)) if have != want => other_term += 1,
            (Some(_), None) => {
                // A row without a term field cannot be attributed; it is
                // counted separately and still projected so no record is
                // silently dropped by the filter.
                unscoped_term += 1;
                matched.push(row.clone());
            }
            _ => matched.push(row.clone()),
        }
    }
    json!({
        "schema_version": 1,
        "type": "marks_gsmis",
        "result": "parsed",
        "scope": SCOPE,
        "requested_xnxqdm": requested_term,
        "records": matched,
        "source_row_count": rows.len(),
        "requested_term_match_count": matched.len(),
        "other_term_count": other_term,
        "unscoped_term_row_count": unscoped_term,
        "declared_total": total_size,
        "declared_page_size": page_size,
        "write_operations_performed": false,
    })
}

fn marks_request(
    client: &reqwest::blocking::Client,
    cookie: reqwest::header::HeaderValue,
    page_number: usize,
) -> Result<reqwest::blocking::Request, Error> {
    let mut request = session_request(client, MARKS_URL, cookie, MARKS_REFERER)
        .form(&[
            ("pageSize", READ_PAGE_SIZE.to_string()),
            ("pageNumber", page_number.to_string()),
        ])
        .timeout(std::time::Duration::from_secs(45))
        .header("Accept-Encoding", "identity")
        .build()
        .map_err(|_| session_invalid())?;
    if let Some(value) = request.headers_mut().get_mut("cookie") {
        value.set_sensitive(true);
    }
    Ok(request)
}

struct MarksPage {
    output: Value,
    row_fingerprint: Option<u64>,
    /// Even a parsed response cannot authorize another request after a safety
    /// observation such as Retry-After.
    stop_reason: Option<&'static str>,
}

/// Acquisition is lazy: breaking this loop prevents the next cookie selection,
/// governor reservation and network request. The acquisition callback increments
/// pages_requested only at the actual transmission boundary.
fn collect_marks_pages(
    mut read: impl FnMut(usize, &mut usize, Option<&Value>) -> Result<MarksPage, Error>,
) -> Result<Value, Error> {
    let mut fingerprints = Vec::with_capacity(MAX_PAGES);
    let mut collected: Option<timetable::PrivateValue> = None;
    let mut pages_requested = 0usize;
    let mut page_facts = Vec::new();
    let mut reasons = Vec::new();
    let mut declared_total = None;
    let mut declared_page_size = None;
    for page_number in 1..=MAX_PAGES {
        let prior_records = collected.as_ref().map(|output| &output["records"]);
        let page = match read(page_number, &mut pages_requested, prior_records) {
            Ok(page) => page,
            Err(failure) => {
                // A safety-state persistence failure must retain its pending
                // lease and remain an error, never a successful partial read.
                if collected.is_none()
                    || !matches!(
                        failure.code,
                        "cooldown" | "request_gap" | "scoped_cookie_unusable" | "auth_latched"
                    )
                {
                    return Err(failure);
                }
                reasons.push(failure.code);
                break;
            }
        };
        let mut output = timetable::PrivateValue(page.output);
        let parsed = output["result"] == "parsed";
        let overbound = output["fallback_reason"] == "row_count_exceeds_bound";
        if !parsed && !(overbound && collected.is_some()) {
            // In particular, a later privacy/challenge/session refusal replaces
            // the whole projection. Earlier records may now contain a secret
            // that was only issued on this response.
            output.0["pages_requested"] = json!(pages_requested);
            output.0["page_facts"] = json!(page_facts);
            let reason = output["fallback_reason"].as_str().unwrap_or("page_not_admitted");
            let completeness = json!({
                "complete": false,
                "reasons": [reason],
                "max_pages": MAX_PAGES,
                "max_source_rows": MAX_ROWS,
            });
            output.0["completeness"] = completeness;
            return Ok(std::mem::take(&mut output.0));
        }
        let row_count = output["source_row_count"]
            .as_u64()
            .expect("parsed marks page has a source row count");
        let total = output["declared_total"].as_u64();
        let size = output["declared_page_size"].as_u64();
        page_facts.push(json!({
            "page_number": page_number,
            "requested_page_size": READ_PAGE_SIZE,
            "source_row_count": row_count,
            "declared_total": total,
            "declared_page_size": size,
            "accepted": false,
        }));
        if let Some(fingerprint) = page.row_fingerprint {
            if row_count > 0 && fingerprints.contains(&fingerprint) {
                reasons.push("repeated_source_page");
                break;
            }
            fingerprints.push(fingerprint);
        }
        if let Some(collected) = collected.as_mut() {
            let observed = collected["source_row_count"]
                .as_u64()
                .expect("collected marks have a source row count");
            if overbound || row_count > MAX_ROWS as u64 - observed {
                // A source that overruns its declared final-page remainder
                // cannot make the projection exceed the invocation bound.
                reasons.push("row_count_limit");
                break;
            }
            collected.0["records"]
                .as_array_mut()
                .expect("parsed marks have records")
                .append(
                    output.0["records"]
                        .as_array_mut()
                        .expect("parsed marks have records"),
                );
            for field in [
                "source_row_count",
                "requested_term_match_count",
                "other_term_count",
                "unscoped_term_row_count",
            ] {
                let count = collected[field].as_u64().expect("marks count is an integer")
                    + output[field].as_u64().expect("marks count is an integer");
                collected.0[field] = json!(count);
            }
        } else {
            declared_total = total;
            declared_page_size = size;
            collected = Some(output);
        }
        page_facts.last_mut().expect("page fact was added")["accepted"] = json!(true);
        let observed = collected.as_ref().expect("page was collected")["source_row_count"]
            .as_u64()
            .expect("collected marks have a source row count");
        let mut inconsistent = false;
        if total.is_none() {
            reasons.push("declared_total_unavailable");
            inconsistent = true;
        } else if total != declared_total {
            reasons.push("declared_total_changed");
            inconsistent = true;
        }
        if size.is_none() {
            reasons.push("page_size_unavailable");
            inconsistent = true;
        } else {
            if size != declared_page_size {
                reasons.push("declared_page_size_changed");
                inconsistent = true;
            }
            if size != Some(READ_PAGE_SIZE as u64) {
                reasons.push("declared_page_size_mismatch");
                inconsistent = true;
            }
            if size.is_some_and(|size| size < row_count) {
                reasons.push("declared_page_size_below_observed_rows");
                inconsistent = true;
            }
        }
        if total.is_some_and(|total| total < observed) {
            reasons.push("declared_total_below_observed_rows");
            inconsistent = true;
        }
        if let Some(reason) = page.stop_reason {
            reasons.push(reason);
            break;
        }
        if inconsistent || total == Some(observed) {
            break;
        }
        if row_count < READ_PAGE_SIZE as u64 {
            reasons.push("short_page_before_declared_total");
            break;
        }
        if page_number == MAX_PAGES {
            reasons.push("page_request_limit");
            break;
        }
        let remaining = declared_total.expect("consistent page declares a total") - observed;
        if remaining.min(READ_PAGE_SIZE as u64) > MAX_ROWS as u64 - observed {
            reasons.push("row_count_limit");
            break;
        }
    }
    let mut output = collected.expect("the first admitted page is collected");
    let observed = output["source_row_count"]
        .as_u64()
        .expect("collected marks have a source row count");
    if declared_total.is_some_and(|total| total > observed) {
        reasons.push("declared_total_exceeds_observed_rows");
    }
    if output["unscoped_term_row_count"].as_u64().unwrap_or(0) > 0 {
        reasons.push("unscoped_term_rows");
    }
    output.0["pages_requested"] = json!(pages_requested);
    output.0["page_facts"] = json!(page_facts);
    output.0["completeness"] = json!({
        "complete": reasons.is_empty() && declared_total == Some(observed),
        "reasons": reasons,
        "max_pages": MAX_PAGES,
        "max_source_rows": MAX_ROWS,
    });
    Ok(std::mem::take(&mut output.0))
}

/// One explicit in-memory CAS login to the graduate marks service followed by
/// the wdcjapp application document and at most three `xscjcx.do` reads. The
/// session never persists, refreshes or retries; the issued cookie is used
/// only while this bounded invocation is active.
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
    input_text: &str,
    online: bool,
    network: impl FnOnce() -> Result<(reqwest::blocking::Client, Governor), Error>,
) -> Result<Value, Error> {
    if input_text.len() > SESSION_MAX_INPUT {
        return Err(session_invalid());
    }
    let mut deserializer = serde_json::Deserializer::from_str(input_text);
    let input: SessionInput =
        deserialize_object(&mut deserializer).map_err(|_| session_invalid())?;
    deserializer.end().map_err(|_| session_invalid())?;
    if !input.read.enabled {
        return Ok(with_provenance(json!({"result": "disabled"}), false));
    }
    if let Some(term) = input.read.xnxqdm.as_deref() {
        if !valid_term_code(term) {
            return Err(session_invalid());
        }
    }
    if !input.authorized {
        return Err(error(
            "permission",
            "explicit authorization for one marks authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if *input.intent != format!("LOGIN {} marks", &*input.username) {
        return Err(session_invalid());
    }
    if !online {
        return Err(error(
            "online_required",
            "marks sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let (client, governor) = network()?;
    let mut lease = net::acquire_kind(&governor, RequestKind::Authentication)?;
    let mut page_observed: Option<(u16, Option<String>, bool)> = None;
    let prepared = cas::authenticate_service(&mut lease, &client, CasService::Gsmis, credentials)
        .and_then(|mut session| {
            let url = url::Url::parse(MARKS_URL).map_err(|_| session_invalid())?;
            let page_url = url::Url::parse(MARKS_PAGE_URL).map_err(|_| session_invalid())?;
            let (page_cookie, page_expiry) = session.cookie_header_for_transmission(&page_url)?;
            let page_cookie = page_cookie.ok_or_else(|| {
                error(
                    "authentication_unconfirmed",
                    "the marks application cookie is missing; no entry was sent",
                )
            })?;
            admit_session_read(&mut lease)?;
            if page_expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
                return Err(error(
                    "scoped_cookie_unusable",
                    "the marks cookie expired before application entry; no request was sent",
                ));
            }
            // The wdcjapp document must be entered first: replaying xscjcx
            // without the application entry is refused by the source.
            let mut page = client
                .get(MARKS_PAGE_URL)
                .header("Cookie", page_cookie)
                .header("Accept", "text/html")
                .header("Referer", MARKS_PORTAL_URL)
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
                    "marks application entry failed; no read was sent",
                )
            })?;
            let page = receive_context_response(
                page,
                &mut lease,
                &mut session,
                &page_url,
                &mut page_observed,
            )?;
            screen_context_response(&page, &input.password, &session)?;
            if page.status == 429 || page.retry_after.is_some() {
                return Err(error("cooldown", "marks application entry was deferred"));
            }
            if page.status != 200 {
                return Err(error(
                    "authentication_unconfirmed",
                    "marks application entry was refused by GSMIS; no read was sent",
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
                    "marks application entry was not a nonempty HTML document; no read was sent",
                ));
            }

            let (cookie, expiry) = session.cookie_header_for_transmission(&url)?;
            let cookie = cookie.ok_or_else(|| {
                error(
                    "auth_latched",
                    "the marks session has no usable cookie; no read was sent",
                )
            })?;
            let request = marks_request(&client, cookie, 1)?;
            admit_session_read(&mut lease)?;
            Ok((session, url, expiry, request))
        });
    let (mut session, url, cookie_expiry, request) = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            if matches!(
                failure.code,
                "governor_error" | "governor_denied" | "governor_unavailable"
            ) {
                return Err(failure);
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
                "handoff_contract_mismatch" => lease.finish_without_request(),
                "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
                _ if page_observed.is_some() => {
                    let (status, retry_after, challenge) =
                        page_observed.take().expect("observed page is present");
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
                    "cannot settle marks authentication attempt",
                )
            })?;
            return Err(failure);
        }
    };
    let mut first = Some((lease, cookie_expiry, request));
    let mut issued = Vec::new();
    let output = collect_marks_pages(|page_number, pages_requested, prior_records| {
        let (lease, expiry, request) = if let Some(first) = first.take() {
            first
        } else {
            let (cookie, expiry) = session.cookie_header_for_transmission(&url)?;
            // Header preparation extends the guard before acquiring a lease.
            // Refuse echoes even if the next request is deferred or expires.
            if let Some(refusal) = prior_page_refusal(prior_records, &|bytes| {
                session.contains_secret_bytes(bytes)
            }) {
                return Ok(refusal);
            }
            let cookie = cookie.ok_or_else(|| {
                error("auth_latched", "the marks session has no usable cookie")
            })?;
            let request = marks_request(&client, cookie, page_number)?;
            let lease = net::acquire(&governor)?;
            (lease, expiry, request)
        };
        read_marks_page(
            &client,
            lease,
            &input,
            &mut session,
            &url,
            &mut issued,
            request,
            expiry,
            pages_requested,
            prior_records,
        )
    })?;
    Ok(with_provenance(output, true))
}

/// A later page can issue a value an earlier page carried before it was
/// identifiable as a credential. Check the earlier projection immediately,
/// before admitting another request or returning any record.
fn screen_prior_records(records: Option<&Value>, contains: &dyn Fn(&[u8]) -> bool) -> BodyScreening {
    let Some(records) = records else {
        return BodyScreening::Clear;
    };
    let Ok(bytes) = serde_json::to_vec(records).map(Zeroizing::new) else {
        return BodyScreening::Unreviewable;
    };
    if contains(&bytes) {
        BodyScreening::Echo
    } else {
        decoded_body_screening(&bytes, contains)
    }
}

fn prior_page_refusal(records: Option<&Value>, contains: &dyn Fn(&[u8]) -> bool) -> Option<MarksPage> {
    let reason = match screen_prior_records(records, contains) {
        BodyScreening::Clear => return None,
        BodyScreening::Echo => "credential_echo",
        BodyScreening::Unreviewable => "response_safety_unreviewed",
    };
    Some(MarksPage {
        output: json!({"schema_version":1,"type":"marks_gsmis","result":"sensitive_response_withheld",
            "fallback_reason":reason,"raw_evidence_withheld":true,"write_operations_performed":false}),
        row_fingerprint: None,
        stop_reason: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn read_marks_page(
    client: &reqwest::blocking::Client,
    mut lease: RequestLease<'_>,
    input: &SessionInput,
    session: &mut cas::ServiceSession,
    url: &url::Url,
    issued: &mut Vec<timetable::IssuedCookies>,
    request: reqwest::blocking::Request,
    cookie_expiry: Option<std::time::SystemTime>,
    pages_requested: &mut usize,
    prior_records: Option<&Value>,
) -> Result<MarksPage, Error> {
    let mut response = match lease.start_request(|| {
        if cookie_expiry.is_some_and(|expiry| std::time::SystemTime::now() >= expiry) {
            None
        } else {
            *pages_requested += 1;
            Some(client.execute(request))
        }
    }) {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(_))) => {
            lease
                .finish(Outcome::NetworkFailure)
                .map_err(|_| error("governor_error", "cannot settle marks request"))?;
            return Err(error(
                "network_error",
                "marks request failed; no automatic retry",
            ));
        }
        Ok(None) => {
            lease
                .finish_without_request()
                .map_err(|_| error("governor_error", "cannot release marks request"))?;
            return Err(error(
                "scoped_cookie_unusable",
                "the marks cookie expired before transmission; no further request was sent",
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
    let cooldown = status == 429 || response.headers().contains_key("retry-after");
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
        .map_err(|_| error("governor_error", "cannot persist marks response headers"))?;
    // Keep the exact issued pairs for echo screening across subsequent pages.
    // The service jar independently applies reviewed scope and expiry rules
    // for transmission and retains retired cookies and complete sent headers.
    let declarations = timetable::IssuedCookies::absorb(response.headers());
    let cookies_reviewed = declarations.complete
        && session.absorb_gsmis_headers(url, response.headers()).is_ok();
    issued.push(declarations);
    let contains = |candidate: &[u8]| {
        net::carries_secret(candidate, &input.username)
            || net::carries_secret(candidate, &input.password)
            || session.contains_secret_bytes(candidate)
            || issued.iter().any(|page| page.contains_secret_bytes(candidate))
    };
    let prior_screening = screen_prior_records(prior_records, &contains);
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
    let body_screening = decoded_body_screening(&bytes, &contains);
    let echo = contains(&bytes)
        || metadata_echo
        || body_screening == BodyScreening::Echo
        || prior_screening == BodyScreening::Echo;
    let mut denied = false;
    let row_fingerprint = Cell::new(None);
    let result = if read_result.is_err() {
        Err(error("network_error", "marks response body read failed"))
    } else if bytes.len() as u64 > SESSION_BODY_LIMIT {
        Err(error(
            "body_limit",
            "marks response exceeds bounded body limit",
        ))
    } else {
        let admission = admit_read_body(
            "marks_gsmis",
            status,
            content_type.as_deref(),
            &bytes,
            assessment,
            ReadScreening {
                header_challenge,
                metadata_echo,
                metadata_unreviewed: !cookies_reviewed,
                echo,
                body_unreviewed: body_screening == BodyScreening::Unreviewable
                    || prior_screening == BodyScreening::Unreviewable
                    || !cookies_reviewed,
            },
            |body| parse_marks_page(body, input.read.xnxqdm.as_deref(), &row_fingerprint),
        );
        denied = admission.denied;
        Ok(admission.output)
    };
    drop(response);
    if denied && !challenge {
        lease
            .finish(Outcome::CredentialRejected)
            .map_err(|_| error("governor_error", "cannot settle marks session denial"))?;
    } else {
        lease
            .finish(Outcome::Http {
                status,
                retry_after: retry_after.as_deref(),
                challenge,
                network_failure: incomplete,
            })
            .map_err(|_| error("governor_error", "cannot settle marks request"))?;
    }
    result.map(|output| MarksPage {
        output,
        row_fingerprint: row_fingerprint.get(),
        stop_reason: cooldown.then_some("cooldown"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(inner: &str) -> String {
        format!(r#"{{"code":"0","datas":{{"xscjcx":{{{inner}}}}}}}"#)
    }

    fn fixture_page(start: usize, count: usize, total: usize, size: usize) -> MarksPage {
        let rows: Vec<_> = (start..start + count)
            .map(|index| json!({"index":index,"XNXQDM":if index % 2 == 0 { "20261" } else { "20252" }}))
            .collect();
        let raw = body(&format!(r#""totalSize":{total},"pageSize":{size},"rows":{}"#, json!(rows)));
        fixture_parse(&raw, Some("20261"))
    }

    fn fixture_parse(raw: &str, term: Option<&str>) -> MarksPage {
        let fingerprint = Cell::new(None);
        MarksPage {
            output: parse_marks_page(raw, term, &fingerprint),
            row_fingerprint: fingerprint.get(),
            stop_reason: None,
        }
    }

    fn collect_fixture(pages: impl IntoIterator<Item = MarksPage>) -> Value {
        let mut pages = pages.into_iter();
        collect_marks_pages(|number, sent, _| {
            assert_eq!(number, *sent + 1);
            *sent += 1;
            Ok(pages.next().expect("pagination requested an unexpected page"))
        })
        .unwrap()
    }

    fn parse_marks(raw: &str, term: Option<&str>) -> Value {
        collect_fixture([fixture_parse(raw, term)])
    }

    #[test]
    fn fixed_request_size_preserves_every_page_offset() {
        let client = reqwest::blocking::Client::new();
        for page_number in 1..=MAX_PAGES {
            let request = marks_request(
                &client,
                reqwest::header::HeaderValue::from_static("GS_SESSIONID=fixture-cookie"),
                page_number,
            )
            .unwrap();
            let form = request.body().and_then(|body| body.as_bytes()).unwrap();
            let expected = format!("pageSize=200&pageNumber={page_number}");
            assert_eq!(form, expected.as_bytes());
            assert!(request.headers()["cookie"].is_sensitive());
        }
    }

    #[test]
    fn paginated_rows_remain_ordered_and_the_bound_is_before_filtering() {
        let output = collect_fixture([
            fixture_page(0, 200, 512, 200),
            fixture_page(200, 200, 512, 200),
            fixture_page(400, 112, 512, 200),
        ]);
        assert_eq!(output["pages_requested"], 3);
        assert_eq!(output["source_row_count"], 512);
        assert_eq!(output["requested_term_match_count"], 256);
        assert_eq!(output["other_term_count"], 256);
        assert_eq!(output["page_facts"][2]["source_row_count"], 112);
        assert_eq!(output["page_facts"][2]["accepted"], true);
        assert_eq!(output["completeness"]["complete"], true);
        let indices: Vec<_> = output["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["index"].as_u64().unwrap())
            .collect();
        assert_eq!(indices, (0..512).step_by(2).collect::<Vec<_>>());
    }

    #[test]
    fn row_limit_prevents_request_or_rejects_entire_overflowing_page() {
        let output = collect_fixture([
            fixture_page(0, 200, 513, 200),
            fixture_page(200, 200, 513, 200),
        ]);
        assert_eq!(output["pages_requested"], 2);
        assert_eq!(output["source_row_count"], 400);
        assert_eq!(output["completeness"]["complete"], false);
        assert_eq!(output["completeness"]["reasons"][0], "row_count_limit");

        for count in [113, 513] {
            let output = collect_fixture([
                fixture_page(0, 200, 512, 200),
                fixture_page(200, 200, 512, 200),
                fixture_page(400, count, 512, 200),
            ]);
            assert_eq!(output["pages_requested"], 3);
            assert_eq!(output["source_row_count"], 400);
            assert_eq!(output["completeness"]["complete"], false);
            assert_eq!(output["page_facts"][2]["source_row_count"], count as u64);
            assert_eq!(output["page_facts"][2]["accepted"], false);
            assert!(output.get("raw_response_base64").is_none());
        }
    }

    #[test]
    fn repeated_source_page_cannot_complete_collection() {
        let output = collect_fixture([fixture_page(0, 200, 400, 200), fixture_page(0, 200, 400, 200)]);
        assert_eq!(output["pages_requested"], 2);
        assert_eq!(output["source_row_count"], 200);
        assert_eq!(output["page_facts"][1]["accepted"], false);
        assert_eq!(output["completeness"]["complete"], false);
        assert_eq!(output["completeness"]["reasons"][0], "repeated_source_page");
    }

    #[test]
    fn terminal_and_inconsistent_pages_stop_before_another_request() {
        for count in [0, 200] {
            let output = collect_fixture([fixture_page(0, count, count, 200)]);
            assert_eq!(output["pages_requested"], 1);
            assert_eq!(output["completeness"]["complete"], true);
        }
        for (count, total, size, reason) in [
            (200, 499, 200, "declared_total_changed"),
            (200, 500, 199, "declared_page_size_changed"),
            (50, 500, 200, "short_page_before_declared_total"),
        ] {
            let output = collect_fixture([
                fixture_page(0, 200, 500, 200),
                fixture_page(200, count, total, size),
            ]);
            assert_eq!(output["pages_requested"], 2);
            assert_eq!(output["completeness"]["complete"], false);
            assert_eq!(output["completeness"]["reasons"][0], reason);
        }
    }

    #[test]
    fn cooldown_privacy_and_unsent_expiry_stop_the_collection() {
        let mut cooldown = fixture_page(0, 200, 400, 200);
        cooldown.stop_reason = Some("cooldown");
        let output = collect_fixture([cooldown]);
        assert_eq!(output["pages_requested"], 1);
        assert_eq!(output["completeness"]["reasons"][0], "cooldown");

        for reason in ["credential_echo", "challenge_requires_human", "session_expired"] {
            let output = collect_fixture([
                fixture_page(0, 200, 500, 200),
                MarksPage {
                    output: json!({"result":"sensitive_response_withheld","fallback_reason":reason}),
                    row_fingerprint: None,
                    stop_reason: None,
                },
            ]);
            assert_eq!(output["pages_requested"], 2);
            assert_eq!(output["completeness"]["reasons"][0], reason);
            assert!(output.get("records").is_none());
        }

        let output = collect_marks_pages(|page, sent, _| match page {
            1 => {
                *sent += 1;
                Ok(fixture_page(0, 200, 500, 200))
            }
            2 => Err(error("scoped_cookie_unusable", "synthetic expiry before send")),
            _ => panic!("a request followed credential expiry"),
        })
        .unwrap();
        assert_eq!(output["pages_requested"], 1);
        assert_eq!(output["completeness"]["complete"], false);
        assert_eq!(output["completeness"]["reasons"][0], "scoped_cookie_unusable");
    }

    #[test]
    fn newly_issued_cookie_is_screened_against_prior_records() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};

        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("GS_SESSIONID=fixture-page-cookie; Path=/gsapp/"),
        );
        let issued = timetable::IssuedCookies::absorb(&headers);
        let encoded_pair = STANDARD.encode("GS_SESSIONID=fixture-page-cookie");
        let issued_guard = |bytes: &[u8]| issued.contains_secret_bytes(bytes);
        assert_eq!(
            screen_prior_records(Some(&json!([{"KCMC":encoded_pair}])), &issued_guard),
            BodyScreening::Echo
        );
        assert_eq!(
            screen_prior_records(Some(&json!([{"KCMC":"Course A"}])), &issued_guard),
            BodyScreening::Clear
        );
        let sent_header = "GS_SESSIONID=page-cookie-37; route=route-cookie-09";
        let combined = STANDARD.encode(sent_header);
        let historical_guard = |bytes: &[u8]| {
            issued_guard(bytes) || net::carries_secret(bytes, sent_header)
        };
        assert_eq!(
            screen_prior_records(Some(&json!([{"KCMC":combined}])), &historical_guard),
            BodyScreening::Echo
        );
    }

    #[test]
    fn a_candidate_cookie_header_withholds_prior_records_before_acquisition() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let header = "GS_SESSIONID=first-example-37; route=second-example-09";
        let mut first = Some(fixture_page(0, 200, 400, 200));
        first.as_mut().unwrap().output["records"][0]["KCMC"] = json!(STANDARD.encode(header));
        let output = collect_marks_pages(|page, sent, prior| {
            if page == 1 {
                *sent += 1;
                return Ok(first.take().unwrap());
            }
            prior_page_refusal(prior, &|bytes| net::carries_secret(bytes, header))
                .ok_or_else(|| error("cooldown", "deferred synthetic acquisition"))
        }).unwrap();
        assert_eq!(output["pages_requested"], 1);
        assert_eq!(output["result"], "sensitive_response_withheld");
        assert_eq!(output["fallback_reason"], "credential_echo");
        assert!(output.get("records").is_none());
    }

    #[test]
    fn invalid_json_is_labeled_fallback_never_rows() {
        let output = parse_marks("{not json", None);
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["fallback_reason"], "invalid_json");
        assert_eq!(output["type"], "marks_gsmis");
        assert!(output.get("records").is_none());
    }

    #[test]
    fn screened_fallback_retains_exact_source_bytes() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let bytes = br#"{"code":"0","datas":{}}"#;
        let admission = admit_read_body(
            "marks_gsmis",
            200,
            Some("application/json"),
            bytes,
            crate::html::ChallengeAssessment::Clear,
            ReadScreening::default(),
            |body| parse_marks_page(body, None, &Cell::new(None)),
        );
        let output = admission.output;
        assert_eq!(output["fallback_reason"], "unrecognized_data_shape");
        let encoded = output["raw_response_base64"].as_str().unwrap();
        assert_eq!(STANDARD.decode(encoded).unwrap(), bytes);
    }

    #[test]
    fn non_zero_code_is_business_error_not_rows() {
        let output = parse_marks(r#"{"code":"9","msg":"denied"}"#, None);
        assert_eq!(output["result"], "business_error");
        assert_eq!(output["upstream_code"], "9");
        assert_eq!(output["upstream_message"], "denied");
        assert!(output.get("records").is_none());
    }

    #[test]
    fn missing_section_or_rows_is_fallback_not_empty_list() {
        for raw in [
            r#"{"code":"0","datas":{}}"#,
            &body(r#""totalSize":3"#),
            r#"{"code":"0","datas":{"xscjcx":{"rows":{"not":"array"}}}}"#,
        ] {
            let output = parse_marks(raw, None);
            assert_eq!(output["result"], "fallback", "{raw}");
            assert_eq!(output["fallback_reason"], "unrecognized_data_shape");
            assert!(output.get("records").is_none());
        }
    }

    #[test]
    fn rows_project_verbatim_and_completeness_reports_facts() {
        let raw = body(
            r#""totalSize":2,"pageSize":200,"rows":[{"XNXQDM":"20261","KCMC":"a","CJ":90.5},{"XNXQDM":"20261","KCMC":"b","CJ":60}]"#,
        );
        let output = parse_marks(&raw, None);
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["records"].as_array().unwrap().len(), 2);
        assert_eq!(output["records"][0]["KCMC"], "a");
        assert_eq!(output["records"][0]["CJ"], 90.5);
        assert_eq!(output["declared_total"], 2);
        assert_eq!(output["completeness"]["complete"], true);
        assert_eq!(
            output["completeness"]["reasons"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn term_filter_counts_without_emitting_other_terms() {
        let raw = body(
            r#""totalSize":3,"pageSize":200,"rows":[{"XNXQDM":"20261","KCMC":"a"},{"XNXQDM":"20252","KCMC":"b"},{"KCMC":"c"}]"#,
        );
        let output = parse_marks(&raw, Some("20261"));
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["requested_term_match_count"], 2);
        assert_eq!(output["other_term_count"], 1);
        assert_eq!(output["unscoped_term_row_count"], 1);
        let names: Vec<&str> = output["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row.get("KCMC").and_then(Value::as_str))
            .collect();
        assert_eq!(names, ["a", "c"]);
        assert!(
            output["completeness"]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "unscoped_term_rows")
        );
        assert_eq!(output["completeness"]["complete"], false);
    }

    #[test]
    fn declared_total_above_rows_is_incomplete() {
        let raw = body(r#""totalSize":5,"pageSize":200,"rows":[{"XNXQDM":"20261"}]"#);
        let output = parse_marks(&raw, None);
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["completeness"]["complete"], false);
        assert!(
            output["completeness"]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "declared_total_exceeds_observed_rows")
        );
    }

    #[test]
    fn overbound_row_count_falls_back_instead_of_truncating() {
        let rows = std::iter::repeat(r#"{"XNXQDM":"20261"}"#)
            .take(MAX_ROWS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let raw = body(&format!(r#""rows":[{rows}]"#));
        let output = parse_marks(&raw, None);
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["fallback_reason"], "row_count_exceeds_bound");
    }

    #[test]
    fn missing_pagination_facts_stay_incomplete() {
        let raw = body(r#""rows":[{"XNXQDM":"20261"}]"#);
        let output = parse_marks(&raw, None);
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["completeness"]["complete"], false);
        assert!(
            output["completeness"]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "declared_total_unavailable")
        );
    }
}

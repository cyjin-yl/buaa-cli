//! Graduate marks session: one explicit in-memory CAS login to GSMIS, one
//! `wdcjapp` application document and exactly one `xscjcx.do` read. Secrets
//! are stdin-only inputs; they are never persisted, logged or placed inside a
//! generic Value tree. The read performs no writes, retries, refreshes or
//! pagination. Session cookies issued by the application and read responses
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
use std::io::Read;
use zeroize::Zeroizing;

use crate::{
    governor::{Governor, Outcome, RequestKind},
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
/// One bounded read page; more source rows than this keep `complete: false`
/// rather than silently truncating a projection the caller trusts.
const READ_PAGE_SIZE: usize = 200;
/// Rows are projected verbatim; a source page larger than the projection
/// bound falls back instead of dropping tail rows uncounted.
const MAX_ROWS: usize = 512;
const MARKS_PAGE_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdcjapp/*default/index.do";
const MARKS_PORTAL_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/yjsemaphome/portal/index.do";
const MARKS_URL: &str = "https://gsmis.buaa.edu.cn/gsapp/sys/wdcjapp/modules/wdcj/xscjcx.do";
const MARKS_REFERER: &str = MARKS_PAGE_URL;
const SCOPE: &str = "one HTTPS response datas.xscjcx envelope only; rows are projected in source order without deduplication, synthesis or field review; totalSize/pageSize are reported as declared facts, and requested-xnxqdm filtering counts non-matching rows without emitting them";

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
fn parse_marks(body: &str, requested_term: Option<&str>) -> Value {
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
        });
    }
    let total_size = section.get("totalSize").and_then(Value::as_u64);
    let page_size = section.get("pageSize").and_then(Value::as_u64);
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
    let complete = match (total_size, page_size) {
        (Some(total), Some(page)) => total == rows.len() as u64 && page >= rows.len() as u64,
        _ => false,
    };
    let mut reasons = Vec::new();
    if total_size.is_none() {
        reasons.push("declared_total_unavailable");
    }
    if page_size.is_none() {
        reasons.push("page_size_unavailable");
    }
    if total_size.is_some_and(|total| total > rows.len() as u64) {
        reasons.push("declared_total_exceeds_observed_rows");
    }
    if total_size.is_some_and(|total| total < rows.len() as u64) {
        reasons.push("declared_total_below_observed_rows");
    }
    if page_size.is_some_and(|page| page < rows.len() as u64) {
        reasons.push("declared_page_size_below_observed_rows");
    }
    if unscoped_term > 0 {
        reasons.push("unscoped_term_rows");
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
        "completeness": {
            "complete": complete && reasons.is_empty(),
            "reasons": reasons,
            "single_page": "one fixed pageSize=200&pageNumber=1 request; no pagination contract is reviewed and no second request is ever issued",
        },
        "write_operations_performed": false,
    })
}

fn marks_request(
    client: &reqwest::blocking::Client,
    cookie: reqwest::header::HeaderValue,
) -> reqwest::blocking::RequestBuilder {
    session_request(client, MARKS_URL, cookie, MARKS_REFERER).form(&[
        ("pageSize", READ_PAGE_SIZE.to_string()),
        ("pageNumber", "1".to_owned()),
    ])
}

/// One explicit in-memory CAS login to the graduate marks service followed by
/// the wdcjapp application document and exactly one `xscjcx.do` read. The
/// session never persists, refreshes or retries; the issued cookie is used
/// for the single read only.
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
            let builder = marks_request(&client, cookie);
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
    // GSMIS re-issues its session cookie on the read. Absorb the declarations
    // into the invocation-only jar so their values join the credential screen;
    // the read remains terminal and nothing is persisted or replayed.
    let issued = timetable::IssuedCookies::absorb(response.headers());
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
    let issued_screening = if issued.entries.is_empty() {
        BodyScreening::Clear
    } else {
        decoded_body_screening(&bytes, &|candidate: &[u8]| {
            issued.contains_secret_bytes(candidate)
        })
    };
    let echo = contains(&bytes)
        || issued.contains_secret_bytes(&bytes)
        || metadata_echo
        || body_screening == BodyScreening::Echo
        || issued_screening == BodyScreening::Echo;
    let mut denied = false;
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
                metadata_unreviewed: !issued.complete,
                echo,
                body_unreviewed: body_screening == BodyScreening::Unreviewable
                    || issued_screening == BodyScreening::Unreviewable
                    || !issued.complete,
            },
            |body| parse_marks(body, input.read.xnxqdm.as_deref()),
        );
        denied = admission.denied;
        Ok(admission.output)
    };
    drop(response);
    if denied {
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
    result.map(|output| with_provenance(output, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(inner: &str) -> String {
        format!(r#"{{"code":"0","datas":{{"xscjcx":{{{inner}}}}}}}"#)
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
            |body| parse_marks(body, None),
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

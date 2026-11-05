use std::collections::BTreeMap;

use base64::Engine;
use chrono::{NaiveDate, NaiveDateTime};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::net::{ArchiveClient, CacheStatus, Error, Response};

const MAX_INPUT: usize = 32 * 1024;
const MAX_URL: usize = 8192;
const MAX_CURSOR: usize = 4096;
const MAX_CDX: usize = 16 * 1024 * 1024;
/// Hard bound on a capture body that may be preserved verbatim. The transport
/// already refuses responses above its own, larger bound, so this bound is
/// reachable and is enforced before any byte is re-encoded or exported.
const MAX_CAPTURE: usize = 4 * 1024 * 1024;
const REDIRECT_REFUSED: &str = "redirect_not_followed";
const SOURCE_MISMATCH: &str = "response_not_from_requested_source";
const ATTRIBUTION_INVALID: &str = "memento_attribution_invalid";
const BODY_OVER_BOUND: &str = "body_exceeds_capture_bound";
const FIELDS: [&str; 7] = [
    "urlkey",
    "timestamp",
    "original",
    "mimetype",
    "statuscode",
    "digest",
    "length",
];

fn invalid() -> Error {
    Error::new("invalid_input", "Invalid archive query.")
}

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "Archive response does not establish the requested provenance.",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupInput {
    url: String,
    from: Option<String>,
    to: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    cursor: Option<String>,
}

fn default_limit() -> usize {
    100
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureInput {
    url: String,
    timestamp: String,
}

fn original_url(value: &str) -> Result<Url, Error> {
    if value.is_empty()
        || value.len() > MAX_URL
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
        || value.contains(['*', '#', '\\'])
    {
        return Err(invalid());
    }
    let parsed = Url::parse(value).map_err(|_| invalid())?;
    let authority = value
        .split_once("://")
        .ok_or_else(invalid)?
        .1
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(invalid)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || authority.is_empty()
        || authority.contains('@')
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(parsed)
}

fn timestamp(value: &str) -> Result<NaiveDateTime, Error> {
    if value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let part = |range: std::ops::Range<usize>| -> Result<u32, Error> {
        value[range].parse().map_err(|_| invalid())
    };
    let year = part(0..4)?;
    if year == 0 {
        return Err(invalid());
    }
    NaiveDate::from_ymd_opt(year as i32, part(4..6)?, part(6..8)?)
        .and_then(|d| d.and_hms_opt(part(8..10).ok()?, part(10..12).ok()?, part(12..14).ok()?))
        .ok_or_else(invalid)
}

/// The archive indexes a resource scheme-insensitively, so an archived row may
/// spell the same resource with either HTTP scheme. Nothing else may differ:
/// host, port, path and query must all describe the queried resource.
fn same_resource(expected: &Url, candidate: &Url) -> bool {
    expected.port() == candidate.port()
        && expected.path() == candidate.path()
        && expected.query() == candidate.query()
        && expected
            .host_str()
            .zip(candidate.host_str())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn datetime(value: NaiveDateTime) -> String {
    value.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// CDX continuation keys are already application/x-www-form-urlencoded values.
// Decode once, then let Url encode the resulting single parameter, never a query.
fn decode_cursor(value: &str) -> Result<String, Error> {
    if value.is_empty()
        || value.len() > MAX_CURSOR
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'&' || b == b'=' || b == b'#')
    {
        return Err(invalid());
    }
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = bytes.get(i + 1..i + 3).ok_or_else(invalid)?;
                let hex = std::str::from_utf8(pair).map_err(|_| invalid())?;
                decoded.push(u8::from_str_radix(hex, 16).map_err(|_| invalid())?);
                i += 3;
            }
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| invalid())?;
    if decoded.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(decoded)
}

// A CDX resume key is "<urlkey> <timestamp>!". The urlkey is the index key the
// page continues, so a page that is not about that exact key is refused.
fn cursor_urlkey(value: &str) -> Result<&str, Error> {
    let (urlkey, position) = value.split_once(' ').ok_or_else(unavailable)?;
    if urlkey.is_empty() || position.is_empty() {
        return Err(unavailable());
    }
    Ok(urlkey)
}

fn lookup_request(input: &str) -> Result<(LookupInput, Url), Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let query: LookupInput = serde_json::from_str(input).map_err(|_| invalid())?;
    original_url(&query.url)?;
    if !(1..=1000).contains(&query.limit) {
        return Err(invalid());
    }
    let from = query.from.as_deref().map(timestamp).transpose()?;
    let to = query.to.as_deref().map(timestamp).transpose()?;
    if from.zip(to).is_some_and(|(from, to)| from > to) {
        return Err(invalid());
    }
    let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;
    let mut url =
        Url::parse("https://web.archive.org/cdx/search/cdx").map_err(|_| unavailable())?;
    {
        let mut params = url.query_pairs_mut();
        params
            .append_pair("url", &query.url)
            .append_pair("matchType", "exact")
            .append_pair("output", "json")
            .append_pair("gzip", "false")
            .append_pair("fl", &FIELDS.join(","))
            .append_pair("limit", &query.limit.to_string())
            .append_pair("showResumeKey", "true");
        if let Some(from) = &query.from {
            params.append_pair("from", from);
        }
        if let Some(to) = &query.to {
            params.append_pair("to", to);
        }
        if let Some(cursor) = &cursor {
            params.append_pair("resumeKey", cursor);
        }
    }
    Ok((query, url))
}

fn capture_request(input: &str) -> Result<(CaptureInput, Url), Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let query: CaptureInput = serde_json::from_str(input).map_err(|_| invalid())?;
    original_url(&query.url)?;
    timestamp(&query.timestamp)?;
    let raw = format!(
        "https://web.archive.org/web/{}id_/{}",
        query.timestamp, query.url
    );
    let url = Url::parse(&raw).map_err(|_| invalid())?;
    // URL parsing must not silently remove dot segments or rewrite path/query bytes.
    if url.as_str() != raw {
        return Err(Error::new(
            "unsupported",
            "Original URL cannot be replayed without changing its spelling.",
        ));
    }
    Ok((query, url))
}

pub fn lookup(input: &str, client: &ArchiveClient) -> Result<Value, Error> {
    let (query, source) = lookup_request(input)?;
    let identity = cursor_scope_identity(&query);
    if let Some(cursor) = query.cursor.as_deref().map(decode_cursor).transpose()? {
        client.verify_cursor_scope(&cursor, &identity)?;
    }
    let value = client.get(&source, false, |response| {
        normalize_lookup(&query, &source, response)
    })?;
    if let Some(next) = value["next_cursor"].as_str() {
        let decoded = decode_cursor(next).map_err(|_| unavailable())?;
        client.record_cursor_scope(&decoded, &identity)?;
    }
    Ok(value)
}

/// Stable identity of the query a resume cursor is bound to: the cursor may
/// only continue the exact query (url, from, to, limit) that minted it.
fn cursor_scope_identity(query: &LookupInput) -> String {
    format!(
        "{}|{}|{}|{}",
        query.url,
        query.from.as_deref().unwrap_or("-"),
        query.to.as_deref().unwrap_or("-"),
        query.limit
    )
}

pub fn capture(input: &str, client: &ArchiveClient) -> Result<Value, Error> {
    let (query, source) = capture_request(input)?;
    let expected_date = timestamp(&query.timestamp)?
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    client.get_with_archive_status_and_persistence(
        &source,
        true,
        |status, headers| {
            (400..=599).contains(&status)
                && valid_memento_attribution(&query, &expected_date, headers)
        },
        // Only admitted captures may persist: a refused or unverified body is
        // reported with its facts and is never retained as the official replay.
        |value: &Value, _| value["result"] == "capture_found",
        |response| normalize_capture(&query, &source, response),
    )
}

fn retrieval(response: &Response) -> Value {
    json!({
        "source_url": response.url,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "cache_status": response.cache_status,
        "revalidated_at_unix_ms": response.revalidated_at_unix_ms,
        "revalidation_status": response.revalidation_status,
        "response_body_sha256": response.sha256,
        "response_body_byte_length": response.body.len(),
        "http": { "status": response.status, "headers": response.headers },
        "trust": "archive_reported; local_sha256_verifies_retrieved_bytes_only"
    })
}

fn optional_number(value: &str) -> Result<Option<u64>, Error> {
    if value == "-" {
        return Ok(None);
    }
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(unavailable());
    }
    value.parse().map(Some).map_err(|_| unavailable())
}

fn normalize_lookup(
    query: &LookupInput,
    source: &Url,
    response: &Response,
) -> Result<Value, Error> {
    if response.status != 200 || response.url != source.as_str() || response.body.len() > MAX_CDX {
        return Err(unavailable());
    }
    let rows: Vec<Vec<String>> =
        serde_json::from_slice(&response.body).map_err(|_| unavailable())?;
    if rows.len() > query.limit + 3 {
        return Err(unavailable());
    }
    let mut captures = Vec::new();
    let mut next_cursor = None;
    // Every row must describe the queried resource, and a resumed page must
    // continue the exact index key its cursor was issued for; an unrelated
    // snapshot can therefore never be reported as this query's capture.
    let expected = original_url(&query.url)?;
    let requested_cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;
    let requested_key = requested_cursor.as_deref().map(cursor_urlkey).transpose()?;
    let mut page_key: Option<&str> = None;
    if let Some(header) = rows.first() {
        if header.len() < FIELDS.len() || header.len() > 32 {
            return Err(unavailable());
        }
        let mut columns = BTreeMap::new();
        for (index, field) in header.iter().enumerate() {
            if field.is_empty()
                || field.len() > 64
                || !field
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || columns.insert(field.as_str(), index).is_some()
            {
                return Err(unavailable());
            }
        }
        let mut indexes = [0; FIELDS.len()];
        for (i, field) in FIELDS.iter().enumerate() {
            indexes[i] = *columns.get(field).ok_or_else(unavailable)?;
        }
        let mut end = rows.len();
        if end >= 3 && rows[end - 2].is_empty() {
            let last = &rows[end - 1];
            if last.len() != 1 {
                return Err(unavailable());
            }
            decode_cursor(&last[0]).map_err(|_| unavailable())?;
            next_cursor = Some(last[0].clone());
            end -= 2;
        }
        if end - 1 > query.limit {
            return Err(unavailable());
        }
        for row in &rows[1..end] {
            if row.len() != header.len()
                || row
                    .iter()
                    .any(|v| v.len() > MAX_URL || v.chars().any(char::is_control))
            {
                return Err(unavailable());
            }
            let [
                urlkey,
                capture_time,
                original,
                mimetype,
                status,
                digest,
                length,
            ] = indexes.map(|i| row[i].as_str());
            if urlkey.is_empty()
                || !urlkey.is_ascii()
                || urlkey.bytes().any(|byte| byte.is_ascii_whitespace())
                || requested_key.is_some_and(|key| key != urlkey)
                || page_key.is_some_and(|key| key != urlkey)
            {
                return Err(unavailable());
            }
            page_key = Some(urlkey);
            let parsed_time = timestamp(capture_time).map_err(|_| unavailable())?;
            if query
                .from
                .as_deref()
                .is_some_and(|from| capture_time < from)
                || query.to.as_deref().is_some_and(|to| capture_time > to)
            {
                return Err(unavailable());
            }
            let parsed_original = original_url(original).map_err(|_| unavailable())?;
            if !same_resource(&expected, &parsed_original) {
                return Err(unavailable());
            }
            let status = optional_number(status)?;
            if status.is_some_and(|s| !(100..=599).contains(&s)) {
                return Err(unavailable());
            }
            let length = optional_number(length)?;
            if digest.is_empty() || digest.len() > 256 || !digest.is_ascii() || digest.contains(' ')
            {
                return Err(unavailable());
            }
            captures.push(json!({
                "original_url": original,
                "capture_timestamp": capture_time,
                "capture_datetime": datetime(parsed_time),
                "representation": "archived",
                "publication_date": { "value": null, "confidence": "unknown" },
                "archive_reported": {
                    "http_status": status,
                    "mimetype": if mimetype == "-" { None } else { Some(mimetype) },
                    "digest": if digest == "-" { None } else { Some(digest) },
                    "digest_verified_against_body": false,
                    "archive_record_length": length
                },
                "capture_body_sha256": null,
                "source_url": source.as_str()
            }));
        }
    }
    if let Some(next) = next_cursor.as_deref() {
        let decoded = decode_cursor(next).map_err(|_| unavailable())?;
        // A resume key may only continue the index key of the rows it follows.
        if page_key != Some(cursor_urlkey(&decoded)?) {
            return Err(unavailable());
        }
    }
    Ok(json!({
        "schema_version": 1,
        "type": "archive_lookup",
        "result": if captures.is_empty() { "missing_in_query_scope" } else { "captures_found" },
        "query": {
            "original_url": query.url, "match_type": "exact", "from": query.from,
            "to": query.to, "bounds": "inclusive", "limit": query.limit, "cursor": query.cursor
        },
        "captures": captures,
        "next_cursor": next_cursor,
        "completeness": {
            "scope": "archive_index_query", "page_complete": true,
            "more_results": next_cursor.is_some(), "complete_history": false
        },
        "retrieval": retrieval(response)
    }))
}

// Link delimiters inside quoted parameters or <URI-references> are data.
fn split_links(value: &str, delimiter: char) -> Result<Vec<&str>, Error> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut angle = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if c.is_control() {
            return Err(unavailable());
        }
        if quoted {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if angle {
            if c == '>' {
                angle = false;
            } else if c == '<' {
                return Err(unavailable());
            }
        } else {
            match c {
                '"' => quoted = true,
                '<' => angle = true,
                '>' => return Err(unavailable()),
                _ if c == delimiter => {
                    parts.push(value[start..i].trim());
                    start = i + c.len_utf8();
                }
                _ => {}
            }
        }
    }
    if quoted || angle || escaped {
        return Err(unavailable());
    }
    parts.push(value[start..].trim());
    Ok(parts)
}

fn original_link(value: &str, expected: &str) -> Result<(), Error> {
    if value.len() > 64 * 1024 {
        return Err(unavailable());
    }
    let mut found = false;
    for link in split_links(value, ',')? {
        let parts = split_links(link, ';')?;
        let target = parts[0]
            .strip_prefix('<')
            .and_then(|p| p.strip_suffix('>'))
            .ok_or_else(unavailable)?;
        let mut relation = None;
        let mut alternate_context = false;
        for param in &parts[1..] {
            let (name, raw) = param.split_once('=').ok_or_else(unavailable)?;
            if name.trim().eq_ignore_ascii_case("anchor") {
                alternate_context = true;
            }
            if name.trim().eq_ignore_ascii_case("rel") {
                if relation.is_some() {
                    return Err(unavailable());
                }
                let raw = raw.trim();
                let rel = if raw.starts_with('"') {
                    raw.strip_prefix('"')
                        .and_then(|p| p.strip_suffix('"'))
                        .ok_or_else(unavailable)?
                } else {
                    raw
                };
                if rel.contains(['"', '\\']) || rel.is_empty() {
                    return Err(unavailable());
                }
                relation = Some(rel);
            }
        }
        if relation.is_some_and(|rel| {
            rel.split_ascii_whitespace()
                .any(|r| r.eq_ignore_ascii_case("original"))
        }) {
            if target != expected || alternate_context {
                return Err(unavailable());
            }
            original_url(target).map_err(|_| unavailable())?;
            found = true;
        }
    }
    if found { Ok(()) } else { Err(unavailable()) }
}

fn valid_memento_attribution(
    query: &CaptureInput,
    expected_date: &str,
    headers: &BTreeMap<String, String>,
) -> bool {
    headers
        .get("memento-datetime")
        .is_some_and(|value| value == expected_date)
        && headers
            .get("link")
            .is_some_and(|value| original_link(value, &query.url).is_ok())
}

/// The transport digest must describe the bytes this process actually received:
/// a preserved "original" whose digest disagrees with those bytes is not evidence.
fn verified_digest(response: &Response) -> Result<String, Error> {
    let digest = format!("{:x}", Sha256::digest(&response.body));
    if digest == response.sha256 {
        Ok(digest)
    } else {
        Err(unavailable())
    }
}

/// Fetched bytes that were not admitted as the requested capture: the exact
/// bytes and local digest are kept unless the body exceeds the capture bound,
/// in which case only the digest, length and content type are retained.
fn raw_response(digest: &str, response: &Response, withheld: Option<&'static str>) -> Value {
    json!({
        "content_type": response.headers.get("content-type"),
        "byte_length": response.body.len(),
        "sha256": digest,
        "body_base64": withheld.is_none().then(|| {
            base64::engine::general_purpose::STANDARD.encode(&response.body)
        }),
        "raw_withheld": withheld.is_some(),
        "raw_withheld_reason": withheld
    })
}

fn archive_reported_http(query: &CaptureInput, response: &Response) -> Value {
    json!({
        "status": response.status,
        "memento_datetime": response.headers.get("memento-datetime"),
        "original_link": query.url,
        "content_type": response.headers.get("content-type")
    })
}

struct CaptureFacts {
    result: &'static str,
    capture_datetime: Option<NaiveDateTime>,
    representation: Option<&'static str>,
    immutable_original: Value,
    archive_reported_http: Value,
    raw_response: Value,
    fallback_reason: Option<&'static str>,
}

/// One shape for every capture outcome: bytes, digest, retrieval timestamps and
/// the enforced transport policy are always reported, and `fallback_reason`
/// states why a fetched body was not admitted as the requested capture.
fn capture_output(
    query: &CaptureInput,
    source: &Url,
    response: &Response,
    facts: CaptureFacts,
) -> Value {
    // A cache hit performs no transport read; nothing is ever retried.
    let request_attempts = if response.cache_status == CacheStatus::Hit {
        0
    } else {
        1
    };
    json!({
        "schema_version": 1,
        "type": "archive_capture",
        "result": facts.result,
        "original_url": query.url,
        "requested_timestamp": query.timestamp,
        "capture_datetime": facts.capture_datetime.map(datetime),
        "representation": facts.representation,
        "publication_date": { "value": null, "confidence": "unknown" },
        "immutable_original": facts.immutable_original,
        "archive_reported_http": facts.archive_reported_http,
        "raw_response": facts.raw_response,
        "fallback_reason": facts.fallback_reason,
        "policy": {
            "byte_cap": MAX_CAPTURE,
            "body_within_cap": response.body.len() <= MAX_CAPTURE,
            "redirects": "not_followed",
            "proxy": "refused",
            "request_attempts": request_attempts,
            "retries": 0
        },
        "source_url": source.as_str(),
        "retrieval": retrieval(response)
    })
}

fn normalize_capture(
    query: &CaptureInput,
    source: &Url,
    response: &Response,
) -> Result<Value, Error> {
    let digest = verified_digest(response)?;
    if !(100..=599).contains(&response.status) {
        return Err(unavailable());
    }
    let requested_time = timestamp(&query.timestamp)?;
    let memento = response.headers.get("memento-datetime");
    let link = response.headers.get("link");
    // An archive error page without attribution is not an archived origin 404.
    if matches!(response.status, 404 | 410) && memento.is_none() && link.is_none() {
        return Ok(capture_output(
            query,
            source,
            response,
            CaptureFacts {
                result: "missing_in_query_scope",
                capture_datetime: None,
                representation: None,
                immutable_original: Value::Null,
                archive_reported_http: Value::Null,
                raw_response: Value::Null,
                fallback_reason: None,
            },
        ));
    }
    let expected_date = requested_time
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let attributed = valid_memento_attribution(query, &expected_date, &response.headers);
    // Redirects are never followed: a 3xx body is a redirect descriptor, and a
    // body served for another URL is not this replay. Both keep their bytes and
    // are labelled instead of being reported as the requested capture.
    let refused = if response.url != source.as_str() {
        Some(SOURCE_MISMATCH)
    } else if (300..=399).contains(&response.status) {
        Some(REDIRECT_REFUSED)
    } else if !attributed {
        Some(ATTRIBUTION_INVALID)
    } else {
        None
    };
    let over_bound = response.body.len() > MAX_CAPTURE;
    if let Some(reason) = refused.or(over_bound.then_some(BODY_OVER_BOUND)) {
        let withheld = over_bound.then_some(BODY_OVER_BOUND);
        // Attribution is established only when nothing was refused, so a
        // bound-only refusal may still report the verified capture facts.
        let confirmed = refused.is_none();
        return Ok(capture_output(
            query,
            source,
            response,
            CaptureFacts {
                result: "unverified_capture",
                capture_datetime: confirmed.then_some(requested_time),
                representation: None,
                immutable_original: Value::Null,
                archive_reported_http: if confirmed {
                    archive_reported_http(query, response)
                } else {
                    Value::Null
                },
                raw_response: raw_response(&digest, response, withheld),
                fallback_reason: Some(reason),
            },
        ));
    }
    Ok(capture_output(
        query,
        source,
        response,
        CaptureFacts {
            result: "capture_found",
            capture_datetime: Some(requested_time),
            representation: Some("archived"),
            immutable_original: json!({
                "sha256": digest,
                "byte_length": response.body.len(),
                "body_base64": base64::engine::general_purpose::STANDARD.encode(&response.body)
            }),
            archive_reported_http: archive_reported_http(query, response),
            raw_response: Value::Null,
            fallback_reason: None,
        },
    ))
}

/// Machine-readable stdin and output contracts; publication dates are never inferred.
pub fn schema() -> Value {
    let timestamp = json!({"type":"string", "pattern":"^[0-9]{14}$", "description":"Valid UTC civil date/time YYYYMMDDhhmmss; years 0001..9999, seconds 00..59."});
    let original = json!({"type":"string", "maxLength":MAX_URL, "description":"HTTP(S) URL with host, no userinfo, whitespace, controls, fragment, backslash or wildcard. Original spelling is retained."});
    let cursor = json!({"type":["string","null"], "maxLength":MAX_CURSOR, "description":"CDX query-encoded resume key; pass next_cursor unchanged. Bound to the exact query (url, from, to, limit) that minted it; a cursor from any other query is rejected."});
    let publication = json!({"type":"object", "additionalProperties":false, "required":["value","confidence"], "properties":{"value":{"type":"null"}, "confidence":{"const":"unknown"}}});
    // Why a fetched body was not admitted as the requested capture. A body that
    // was never parsed is preserved verbatim, so its reason is always reported.
    let fallback_reasons = json!({"type":["string","null"], "enum":[REDIRECT_REFUSED, SOURCE_MISMATCH, ATTRIBUTION_INVALID, BODY_OVER_BOUND, null]});
    let raw_body = json!({"anyOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["content_type","byte_length","sha256","body_base64","raw_withheld","raw_withheld_reason"],"properties":{
        "content_type":{"type":["string","null"],"description":"archive-reported content type of the received body"},
        "byte_length":{"type":"integer","minimum":0,"description":"Bytes actually received; may exceed the capture bound when the body was withheld."},
        "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Locally computed digest of the received bytes."},
        "body_base64":{"type":["string","null"],"contentEncoding":"base64","description":"Exact received bytes; null only when withheld by the capture bound."},
        "raw_withheld":{"type":"boolean"},
        "raw_withheld_reason":{"type":["string","null"],"enum":[BODY_OVER_BOUND,null]}
    }}]});
    let capture_policy = json!({"type":"object","additionalProperties":false,"required":["byte_cap","body_within_cap","redirects","proxy","request_attempts","retries"],"properties":{
        "byte_cap":{"const":MAX_CAPTURE},"body_within_cap":{"type":"boolean"},
        "redirects":{"const":"not_followed","description":"A 3xx response is never followed; its body is preserved as unverified_capture."},
        "proxy":{"const":"refused","description":"Direct egress only: no proxy configuration or proxy environment variable is consulted."},
        "request_attempts":{"enum":[0,1],"description":"Transport reads performed by this invocation: 0 for a cache hit, otherwise exactly one."},
        "retries":{"const":0,"description":"A failed or refused capture read is never retried."}
    }});
    let retrieval = json!({"type":"object", "additionalProperties":false, "required":["source_url","fetched_at_unix_ms","cache_status","revalidated_at_unix_ms","revalidation_status","response_body_sha256","response_body_byte_length","http","trust"], "properties":{
        "source_url":{"type":"string"}, "fetched_at_unix_ms":{"type":"integer","minimum":0},
        "cache_status":{"enum":["hit","miss","revalidated"]}, "revalidated_at_unix_ms":{"type":["integer","null"],"minimum":0},
        "revalidation_status":{"type":["integer","null"]}, "response_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
        "response_body_byte_length":{"type":"integer","minimum":0},
        "http":{"type":"object","additionalProperties":false,"required":["status","headers"],"properties":{"status":{"type":"integer"},"headers":{"type":"object","additionalProperties":{"type":"string"}}}},
        "trust":{"const":"archive_reported; local_sha256_verifies_retrieved_bytes_only"}
    }});
    let capture_row = json!({"type":"object","additionalProperties":false,"required":["original_url","capture_timestamp","capture_datetime","representation","publication_date","archive_reported","capture_body_sha256","source_url"],"properties":{
        "original_url":original,"capture_timestamp":timestamp,"capture_datetime":{"type":"string","format":"date-time"},
        "representation":{"const":"archived"},"publication_date":publication,"capture_body_sha256":{"type":"null"},"source_url":{"type":"string"},
        "archive_reported":{"type":"object","additionalProperties":false,"required":["http_status","mimetype","digest","digest_verified_against_body","archive_record_length"],"properties":{
            "http_status":{"type":["integer","null"],"minimum":100,"maximum":599},"mimetype":{"type":["string","null"]},
            "digest":{"type":["string","null"],"description":"Opaque archive-reported digest; not a locally verified resource hash."},"digest_verified_against_body":{"const":false},
            "archive_record_length":{"type":["integer","null"],"minimum":0,"description":"Archive record bytes, not resource content length."}
        }}
    }});
    json!({
        "lookup":{
            "input":{"type":"object","additionalProperties":false,"required":["url"],"properties":{
                "url":original,"from":{"anyOf":[timestamp,{"type":"null"}],"description":"Optional inclusive lower bound: exactly 14 ASCII digits YYYYMMDDhhmmss representing a valid UTC civil date/time, year 0001..9999 and seconds 00..59; no abbreviated year/date. Must not exceed to."},"to":{"anyOf":[timestamp,{"type":"null"}],"description":"Optional inclusive upper bound: exactly 14 ASCII digits YYYYMMDDhhmmss representing a valid UTC civil date/time, year 0001..9999 and seconds 00..59; no abbreviated year/date. Must not precede from."},
                "limit":{"type":"integer","minimum":1,"maximum":1000,"default":100},"cursor":cursor
            }},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","query","captures","next_cursor","completeness","retrieval"],"properties":{
                "schema_version":{"const":1},"type":{"const":"archive_lookup"},
                "result":{"enum":["captures_found","missing_in_query_scope"],"description":"Both results cover the queried resource only; a page whose index key or original URLs describe any other resource is refused instead of reported."},
                "query":{"type":"object","additionalProperties":false,"required":["original_url","match_type","from","to","bounds","limit","cursor"],"properties":{
                    "original_url":original,"match_type":{"const":"exact"},"from":{"anyOf":[timestamp,{"type":"null"}]},"to":{"anyOf":[timestamp,{"type":"null"}]},
                    "bounds":{"const":"inclusive"},"limit":{"type":"integer","minimum":1,"maximum":1000},"cursor":cursor
                }},
                "captures":{"type":"array","maxItems":1000,"items":capture_row,"description":"Rows of the exact index key for the queried resource; capture timestamps stay within the requested bounds."},"next_cursor":cursor,
                "completeness":{"type":"object","additionalProperties":false,"required":["scope","page_complete","more_results","complete_history"],"properties":{
                    "scope":{"const":"archive_index_query"},"page_complete":{"const":true},"more_results":{"type":"boolean"},"complete_history":{"const":false}
                }},"retrieval":retrieval
            }}
        },
        "capture":{
            "input":{"type":"object","additionalProperties":false,"required":["url","timestamp"],"properties":{"url":original,"timestamp":timestamp}},
            "output":{"type":"object","additionalProperties":false,"required":["schema_version","type","result","original_url","requested_timestamp","capture_datetime","representation","publication_date","immutable_original","archive_reported_http","raw_response","fallback_reason","policy","source_url","retrieval"],"properties":{
                "schema_version":{"const":1},"type":{"const":"archive_capture"},
                "result":{"enum":["capture_found","missing_in_query_scope","unverified_capture"],"description":"unverified_capture means a body was fetched but is not claimed as the requested capture; see fallback_reason."},
                "original_url":original,"requested_timestamp":timestamp,"capture_datetime":{"type":["string","null"],"format":"date-time"},
                "representation":{"enum":["archived",null]},"publication_date":publication,"source_url":{"type":"string"},"retrieval":retrieval,
                "immutable_original":{"anyOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["sha256","byte_length","body_base64"],"properties":{
                    "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$","description":"Locally recomputed digest of body_base64; must equal the transport digest."},"byte_length":{"type":"integer","minimum":0},"body_base64":{"type":"string","contentEncoding":"base64"}
                }}],"description":"Present only for capture_found and only within the capture byte bound."},
                "raw_response":raw_body,"fallback_reason":fallback_reasons,"policy":capture_policy,
                "archive_reported_http":{"anyOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["status","memento_datetime","original_link","content_type"],"properties":{
                    "status":{"type":"integer","minimum":100,"maximum":599},"memento_datetime":{"type":"string"},"original_link":{"type":"string"},"content_type":{"type":["string","null"]}
                }}]}
            }}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};

    fn response(source: &Url, body: &[u8]) -> Response {
        Response {
            url: source.to_string(),
            status: 200,
            headers: BTreeMap::new(),
            body: body.to_vec(),
            sha256: format!("{:x}", Sha256::digest(body)),
            fetched_at_unix_ms: 1234,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    fn query() -> (LookupInput, Url) {
        lookup_request(r#"{"url":"https://example.org/a?x=1&y=2","from":"20240229000000","to":"20240229235959"}"#).unwrap()
    }

    #[test]
    fn cdx_named_columns_keep_index_facts_separate_from_verified_bytes() {
        let (query, source) = query();
        let body = br#"[["urlkey","length","digest","original","statuscode","mimetype","timestamp"],["org,example)/a","123","ARCHIVEHASH","http://example.org/a?x=1&y=2","404","text/html","20240229120000"],["org,example)/a","-","-","https://example.org/a?x=1&y=2","-","-","20240229130000"],[],["org%2Cexample%29%2Fa+20240229130000%21"]]"#;
        let result = normalize_lookup(&query, &source, &response(&source, body)).unwrap();
        assert_eq!(
            result["captures"][0]["original_url"],
            "http://example.org/a?x=1&y=2"
        );
        assert_eq!(
            result["captures"][0]["capture_datetime"],
            "2024-02-29T12:00:00Z"
        );
        assert_eq!(
            result["captures"][0]["publication_date"],
            json!({"value":null,"confidence":"unknown"})
        );
        assert_eq!(
            result["captures"][0]["archive_reported"]["http_status"],
            404
        );
        assert_eq!(
            result["captures"][0]["archive_reported"]["archive_record_length"],
            123
        );
        assert_eq!(
            result["captures"][0]["archive_reported"]["digest"],
            "ARCHIVEHASH"
        );
        assert_eq!(
            result["captures"][0]["archive_reported"]["digest_verified_against_body"],
            false
        );
        assert_eq!(result["captures"][0]["capture_body_sha256"], Value::Null);
        assert_eq!(
            result["captures"][1]["archive_reported"]["digest"],
            Value::Null
        );
        assert_eq!(
            result["captures"][1]["archive_reported"]["http_status"],
            Value::Null
        );
        assert_eq!(
            result["retrieval"]["response_body_sha256"],
            format!("{:x}", Sha256::digest(body))
        );
        assert_eq!(result["completeness"]["more_results"], true);
    }

    #[test]
    fn resume_keys_decode_once_without_parameter_injection() {
        let cursor = "org%2Cexample%29%2F+20240229130000%21%26url%3Devil%252F";
        let (_, source) =
            lookup_request(&json!({"url":"https://example.org/","cursor":cursor}).to_string())
                .unwrap();
        let pairs: Vec<_> = source.query_pairs().collect();
        assert_eq!(pairs.iter().filter(|(key, _)| key == "url").count(), 1);
        assert_eq!(
            pairs.iter().find(|(key, _)| key == "resumeKey").unwrap().1,
            "org,example)/ 20240229130000!&url=evil%2F"
        );
        assert!(!source.as_str().contains("org%252C"));
        for invalid_cursor in ["a&url=evil", "abc%", "abc%GG", "%00", "%FF"] {
            assert!(decode_cursor(invalid_cursor).is_err());
        }
    }

    #[test]
    fn resume_key_pages_include_urlkey_without_exposing_it() {
        let cursor = "org%2Cexample%29%2Fa+19980101000001%21";
        let first_input = json!({"url":"https://example.org/a","limit":1}).to_string();
        let (first_query, first_source) = lookup_request(&first_input).unwrap();
        let first_pairs: Vec<_> = first_source.query_pairs().collect();
        assert_eq!(
            first_pairs.iter().find(|(key, _)| key == "fl").unwrap().1,
            FIELDS.join(",")
        );
        assert_eq!(FIELDS[0], "urlkey");

        let first_page = json!([
            FIELDS,
            [
                "org,example)/a",
                "19980101000000",
                "https://example.org/a",
                "text/html",
                "200",
                "HASH1",
                "10"
            ],
            [],
            [cursor]
        ])
        .to_string();
        let first_result = normalize_lookup(
            &first_query,
            &first_source,
            &response(&first_source, first_page.as_bytes()),
        )
        .unwrap();
        assert_eq!(first_result["next_cursor"], cursor);
        assert!(first_result["captures"][0].get("urlkey").is_none());

        let second_input =
            json!({"url":"https://example.org/a","limit":1,"cursor":cursor}).to_string();
        let (second_query, second_source) = lookup_request(&second_input).unwrap();
        let second_pairs: Vec<_> = second_source.query_pairs().collect();
        assert_eq!(
            second_pairs
                .iter()
                .find(|(key, _)| key == "resumeKey")
                .unwrap()
                .1,
            "org,example)/a 19980101000001!"
        );
        assert_eq!(
            second_pairs.iter().find(|(key, _)| key == "fl").unwrap().1,
            FIELDS.join(",")
        );

        let second_page = json!([
            FIELDS,
            [
                "org,example)/a",
                "19980101000002",
                "https://example.org/a",
                "text/html",
                "200",
                "HASH2",
                "12"
            ]
        ])
        .to_string();
        let second_result = normalize_lookup(
            &second_query,
            &second_source,
            &response(&second_source, second_page.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            second_result["captures"][0]["capture_timestamp"],
            "19980101000002"
        );
        assert_eq!(second_result["next_cursor"], Value::Null);
    }

    #[test]
    fn lookup_refuses_rows_for_another_resource() {
        let (query, source) = query();
        let header = json!(FIELDS);
        for original in [
            "https://example.org/other",
            "https://other.example.org/a?x=1&y=2",
            "https://example.org/a?x=1&y=3",
        ] {
            let body = json!([
                header.clone(),
                [
                    "org,example)/a",
                    "20240229120000",
                    original,
                    "text/html",
                    "200",
                    "-",
                    "1"
                ]
            ])
            .to_string();
            assert!(
                normalize_lookup(&query, &source, &response(&source, body.as_bytes())).is_err(),
                "{original}"
            );
        }
        // The index keys the resource scheme-insensitively, so the other HTTP
        // scheme still names the queried resource; no other difference does.
        let body = json!([
            header,
            [
                "org,example)/a",
                "20240229120000",
                "http://example.org/a?x=1&y=2",
                "text/html",
                "200",
                "-",
                "1"
            ]
        ])
        .to_string();
        assert!(normalize_lookup(&query, &source, &response(&source, body.as_bytes())).is_ok());
    }

    #[test]
    fn lookup_refuses_a_page_that_mixes_index_keys() {
        let (query, source) = query();
        let body = json!([
            FIELDS,
            [
                "org,example)/a",
                "20240229120000",
                "https://example.org/a?x=1&y=2",
                "text/html",
                "200",
                "-",
                "1"
            ],
            [
                "org,example)/b",
                "20240229120000",
                "https://example.org/a?x=1&y=2",
                "text/html",
                "200",
                "-",
                "1"
            ]
        ])
        .to_string();
        assert!(normalize_lookup(&query, &source, &response(&source, body.as_bytes())).is_err());
    }

    #[test]
    fn resume_keys_must_continue_the_page_index_key() {
        let (query, source) = query();
        let row = json!([
            "org,example)/a",
            "20240229120000",
            "https://example.org/a?x=1&y=2",
            "text/html",
            "200",
            "-",
            "1"
        ]);
        let page = |cursor: &str| json!([FIELDS, row.clone(), [], [cursor]]);
        let foreign = page("org%2Cexample%29%2Fother+20240229120001%21");
        assert!(
            normalize_lookup(
                &query,
                &source,
                &response(&source, foreign.to_string().as_bytes())
            )
            .is_err()
        );
        let own = page("org%2Cexample%29%2Fa+20240229120001%21");
        let result = normalize_lookup(
            &query,
            &source,
            &response(&source, own.to_string().as_bytes()),
        )
        .unwrap();
        assert_eq!(
            result["next_cursor"],
            "org%2Cexample%29%2Fa+20240229120001%21"
        );
        // A cursor minted for another index key cannot select this page's rows.
        let other = json!({
            "url":"https://example.org/a?x=1&y=2",
            "from":"20240229000000",
            "to":"20240229235959",
            "cursor":"org%2Cexample%29%2Fb+20240229120000%21"
        })
        .to_string();
        let (other_query, other_source) = lookup_request(&other).unwrap();
        let body = json!([FIELDS, row]).to_string();
        assert!(
            normalize_lookup(
                &other_query,
                &other_source,
                &response(&other_source, body.as_bytes())
            )
            .is_err()
        );
    }

    #[test]
    fn cdx_rows_require_valid_internal_urlkeys() {
        let (query, source) = query();
        let empty_urlkey = json!([
            FIELDS,
            [
                "",
                "20240229120000",
                "https://example.org/a",
                "text/html",
                "200",
                "-",
                "1"
            ]
        ])
        .to_string();
        let non_ascii_urlkey = json!([
            FIELDS,
            [
                "org,é)/a",
                "20240229120000",
                "https://example.org/a",
                "text/html",
                "200",
                "-",
                "1"
            ]
        ])
        .to_string();
        for body in [
            r#"[["timestamp","original","mimetype","statuscode","digest","length"]]"#.to_string(),
            empty_urlkey,
            non_ascii_urlkey,
        ] {
            assert!(
                normalize_lookup(&query, &source, &response(&source, body.as_bytes())).is_err()
            );
        }
    }

    #[test]
    fn invalid_dates_and_queries_fail_before_transport() {
        for date in [
            "20230229000000",
            "20240230000000",
            "20241301000000",
            "20240101240000",
            "20240101000060",
            "2024010100000",
            "00000101000000",
        ] {
            assert!(timestamp(date).is_err(), "{date}");
        }
        assert_eq!(
            datetime(timestamp("20000229010203").unwrap()),
            "2000-02-29T01:02:03Z"
        );
        for input in [
            r#"{"url":"https://example.org/","from":"20240229235959","to":"20240229000000"}"#,
            r#"{"url":"https://user@example.org/"}"#,
            r#"{"url":"https://example.org/*"}"#,
            r#"{"url":"https://example.org/#"}"#,
            r#"{"url":"file:///tmp/a"}"#,
            r#"{"url":"https://example.org/","limit":0}"#,
            r#"{"url":"https://example.org/","filter":"x"}"#,
        ] {
            assert!(lookup_request(input).is_err());
        }
    }

    #[test]
    fn missing_index_results_never_claim_complete_history() {
        let (query, source) = query();
        for body in [
            b"[]".as_slice(),
            br#"[["urlkey","timestamp","original","mimetype","statuscode","digest","length"]]"#
                .as_slice(),
        ] {
            let result = normalize_lookup(&query, &source, &response(&source, body)).unwrap();
            assert_eq!(result["result"], "missing_in_query_scope");
            assert_eq!(result["query"]["from"], "20240229000000");
            assert_eq!(result["completeness"]["complete_history"], false);
            assert_eq!(result["next_cursor"], Value::Null);
        }
    }

    #[test]
    fn entire_index_response_must_be_well_formed() {
        let (query, source) = query();
        for body in [
            r#"[["urlkey","timestamp","original","mimetype","statuscode","digest","digest"]]"#,
            r#"[["urlkey","timestamp","original","mimetype","statuscode","digest","length"],["org,example)/a","20240229120000","https://example.org/a","text/html","200","-","1"],["bad"]]"#,
            r#"[["urlkey","timestamp","original","mimetype","statuscode","digest","length"],["org,example)/a","20240230120000","https://example.org/a","text/html","200","-","1"]]"#,
            r#"[["urlkey","timestamp","original","mimetype","statuscode","digest","length"],["org,example)/a","20240229120000","https://example.org/a","text/html","600","-","1"]]"#,
            r#"[["urlkey","timestamp","original","mimetype","statuscode","digest","length"],[],["key"],["extra"]]"#,
            r#"[] trailing"#,
        ] {
            assert!(
                normalize_lookup(&query, &source, &response(&source, body.as_bytes())).is_err()
            );
        }
    }

    fn captured() -> (CaptureInput, Url, Response) {
        let (query, source) = capture_request(
            r#"{"url":"https://example.org/a,b?x=1&y=%2F","timestamp":"20240229120000"}"#,
        )
        .unwrap();
        let mut response = response(&source, b"\x00original\xff");
        response.headers.insert(
            "memento-datetime".into(),
            "Thu, 29 Feb 2024 12:00:00 GMT".into(),
        );
        response.headers.insert("link".into(), format!("<https://web.archive.org/web/20240229120000/https://example.org/a,b>; rel=\"memento\"; title=\"quoted, comma; and \\\"quote\\\"\", <{}>; rel=\"original\"", query.url));
        (query, source, response)
    }

    #[test]
    fn exact_capture_keeps_binary_original_and_unknown_publication_date() {
        let (query, source, mut response) = captured();
        assert_eq!(
            source.as_str(),
            "https://web.archive.org/web/20240229120000id_/https://example.org/a,b?x=1&y=%2F"
        );
        response.status = 404;
        let result = normalize_capture(&query, &source, &response).unwrap();
        assert_eq!(result["result"], "capture_found");
        assert_eq!(result["archive_reported_http"]["status"], 404);
        assert_eq!(
            result["immutable_original"]["sha256"],
            format!("{:x}", Sha256::digest(b"\x00original\xff"))
        );
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(
                result["immutable_original"]["body_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(decoded, b"\x00original\xff");
        assert_eq!(
            result["publication_date"],
            json!({"value":null,"confidence":"unknown"})
        );
    }

    #[test]
    fn nearest_capture_redirect_or_wrong_source_is_never_admitted() {
        let (query, source, mut response) = captured();
        response.headers.insert(
            "memento-datetime".into(),
            "Thu, 29 Feb 2024 12:00:01 GMT".into(),
        );
        let unverified = |response: &Response| {
            let value = normalize_capture(&query, &source, response).unwrap();
            assert_eq!(value["result"], "unverified_capture");
            assert_eq!(value["immutable_original"], Value::Null);
            assert_eq!(value["archive_reported_http"], Value::Null);
            assert_eq!(value["policy"]["request_attempts"], 1);
            assert_eq!(value["policy"]["redirects"], "not_followed");
            assert_eq!(value["policy"]["proxy"], "refused");
            value
        };
        assert_eq!(
            unverified(&response)["fallback_reason"],
            ATTRIBUTION_INVALID
        );
        response.headers.insert(
            "memento-datetime".into(),
            "Thu, 29 Feb 2024 12:00:00 +0000".into(),
        );
        assert_eq!(
            unverified(&response)["fallback_reason"],
            ATTRIBUTION_INVALID
        );
        let (_, _, mut response) = captured();
        response.headers.insert(
            "link".into(),
            "<https://example.org/other>; rel=\"original\"".into(),
        );
        assert_eq!(
            unverified(&response)["fallback_reason"],
            ATTRIBUTION_INVALID
        );
        let (_, _, mut response) = captured();
        response.status = 302;
        // A redirect is never followed: its body is kept, but not as a capture.
        let refused = unverified(&response);
        assert_eq!(refused["fallback_reason"], REDIRECT_REFUSED);
        assert_eq!(refused["raw_response"]["raw_withheld"], false);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(refused["raw_response"]["body_base64"].as_str().unwrap())
                .unwrap(),
            b"\x00original\xff"
        );
        let (_, _, mut response) = captured();
        response.url.push_str("changed");
        assert_eq!(unverified(&response)["fallback_reason"], SOURCE_MISMATCH);
        assert!(
            capture_request(r#"{"url":"https://example.org/a/../b","timestamp":"20240229120000"}"#)
                .is_err()
        );
        let (_, _, mut response) = captured();
        response.headers.insert(
            "link".into(),
            format!(
                "<{}>; rel=\"original\"; anchor=\"https://example.org/other\"",
                query.url
            ),
        );
        assert_eq!(
            unverified(&response)["fallback_reason"],
            ATTRIBUTION_INVALID
        );
    }

    #[test]
    fn capture_bound_withholds_oversized_bodies_without_losing_provenance() {
        let (query, source, mut response) = captured();
        response.body = vec![b'x'; MAX_CAPTURE + 1];
        response.sha256 = format!("{:x}", Sha256::digest(&response.body));
        let result = normalize_capture(&query, &source, &response).unwrap();
        assert_eq!(result["result"], "unverified_capture");
        assert_eq!(result["fallback_reason"], BODY_OVER_BOUND);
        assert_eq!(result["immutable_original"], Value::Null);
        assert_eq!(result["raw_response"]["body_base64"], Value::Null);
        assert_eq!(result["raw_response"]["raw_withheld"], true);
        assert_eq!(
            result["raw_response"]["raw_withheld_reason"],
            BODY_OVER_BOUND
        );
        assert_eq!(result["raw_response"]["byte_length"], MAX_CAPTURE + 1);
        assert_eq!(
            result["raw_response"]["sha256"],
            format!("{:x}", Sha256::digest(&response.body))
        );
        // Attribution preceded the bound, so the verified capture facts remain.
        assert_eq!(result["capture_datetime"], "2024-02-29T12:00:00Z");
        assert_eq!(result["archive_reported_http"]["status"], 200);
        assert_eq!(result["policy"]["byte_cap"], json!(MAX_CAPTURE));
        assert_eq!(result["policy"]["body_within_cap"], false);
        assert_eq!(result["policy"]["request_attempts"], 1);
        assert_eq!(result["policy"]["retries"], 0);
        // A cache hit performs no transport read at all.
        response.cache_status = CacheStatus::Hit;
        let cached = normalize_capture(&query, &source, &response).unwrap();
        assert_eq!(cached["policy"]["request_attempts"], 0);
        assert_eq!(cached["retrieval"]["cache_status"], "hit");
    }

    #[test]
    fn capture_refuses_a_digest_that_does_not_describe_the_received_bytes() {
        let (query, source, mut response) = captured();
        response.sha256 = format!("{:x}", Sha256::digest(b"another body"));
        assert_eq!(
            normalize_capture(&query, &source, &response)
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn unattributed_missing_replay_is_not_original_content() {
        let (query, source, mut response) = captured();
        response.headers.clear();
        for status in [404, 410] {
            response.status = status;
            let result = normalize_capture(&query, &source, &response).unwrap();
            assert_eq!(result["result"], "missing_in_query_scope");
            assert_eq!(result["immutable_original"], Value::Null);
            assert_eq!(result["raw_response"], Value::Null);
            assert_eq!(result["fallback_reason"], Value::Null);
            assert_eq!(result["capture_datetime"], Value::Null);
            assert_eq!(result["retrieval"]["http"]["status"], status);
        }
        response.status = 200;
        // A fetched 200 body without attribution is preserved but never claimed
        // as the requested capture.
        let result = normalize_capture(&query, &source, &response).unwrap();
        assert_eq!(result["result"], "unverified_capture");
        assert_eq!(result["fallback_reason"], ATTRIBUTION_INVALID);
        assert_eq!(result["immutable_original"], Value::Null);
        assert_eq!(result["capture_datetime"], Value::Null);
        assert_eq!(result["raw_response"]["raw_withheld"], false);
    }
}

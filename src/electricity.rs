//! Offline electricity meter parsing, threshold transitions and private state.
//!
//! Live access is deliberately blocked. The upstream directory is
//! unauthenticated and lists other people's card and meter data, so returning
//! it as degradation evidence would violate the restricted-disclosure
//! requirement, and a caller-provided room or card is not an authorization
//! oracle. The blocked [`run`] command therefore performs no campus request,
//! no HTTPS probe and no state write; the observation API persists local data.
//!
//! What is implemented offline is the parsing and alerting contract: strict
//! charset handling (UTF-8 and GBK), directory selection for a sanitized
//! fixture, balance-page parsing with unambiguous element ownership, chart
//! history extraction that never scans JavaScript strings or comments, and
//! edge-triggered threshold transitions with a one-hour cooldown that persist
//! only in the caller's private directory. Synthetic fixtures are not online
//! service acceptance. Reviewed-safe degradation keeps exact original bytes
//! for offline recovery; private, challenge, unsafe-metadata or unreviewable
//! inputs withhold reversible bytes and expose only safe evidence metadata.
//!
//! [`observe_threshold`] consumes a caller-supplied balance. It performs no
//! network request and neither collects nor authenticates any real meter,
//! but it does keep local state: the caller-supplied observation, its
//! threshold, the observation timestamps and the digest of the caller key,
//! inside the private state directory only. Its per-key file lock serializes
//! concurrent processes on one local cache key so a crossing is reported once
//! and the polling floor is not lost; that lock is a local synchronization
//! device, not the shared account governor. The blocked branch of [`run`]
//! performs no request and persists nothing at all.

use crate::governor;
use crate::html::{element_text, inert_element, script_kind, ScriptKind};
use crate::net::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fs2::FileExt;
use scraper::{ElementRef, Html, Node, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_MESSAGE: &str = "上游仅提供明文 HTTP，按项目策略不降级访问";
const PRIVATE_DIR: &str = ".buaa-cli-electricity";
const MIN_POLL_SECONDS: u64 = 900;
const COOLDOWN_SECONDS: u64 = 3600;
const MAX_INTERVAL: u64 = 2_147_483_647;
const MAX_INPUT: usize = 16 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;
const MAX_FIELD: usize = 256;
const MAX_SCRIPT_TEXT: usize = 256 * 1024;
const MAX_ARRAY_ITEMS: usize = 4096;
const MAX_STATE_BYTES: u64 = 64 * 1024;
const LOCK_TIMEOUT_SECONDS: u64 = 30;
const LOCK_POLL_MILLIS: u64 = 5;

/// Every degraded reason the balance parser can report. The list is the
/// published contract, so the runtime and the schema cannot drift apart.
/// `body_limit` belongs to the page parser: the fixture path refuses an
/// oversized body as invalid input before any parsing happens, so a degraded
/// envelope never carries it.
const FALLBACK_REASONS: [&str; 18] = [
    "body_limit",
    "unexpected_content_type",
    "unsupported_charset",
    "charset_decode_failed",
    "balance_values_missing",
    "balance_values_ambiguous",
    "room_address_missing",
    "recharge_records_missing",
    "history_missing",
    "history_ambiguous",
    "script_unlexable",
    "script_text_limit",
    "internal_selector",
    "response_withheld",
    "unsafe_response_metadata",
    "sensitive_response_material",
    "challenge_detected",
    "response_safety_unreviewed",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    identity_no: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Location {
    campus: String,
    building: String,
    floor: String,
    room: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MeterSelector {
    Identity(Identity),
    Location(Location),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    operation: String,
    selector: MeterSelector,
    authorization_confirmed: bool,
    #[serde(default)]
    threshold_kwh: Option<f64>,
    #[serde(default, deserialize_with = "interval")]
    poll_interval_seconds: Option<u64>,
}

fn invalid(message: &'static str) -> Error {
    Error::new("invalid_input", message)
}

fn local_error() -> Error {
    Error::new(
        "unavailable",
        "private electricity storage is unavailable or invalid",
    )
}

/// A polling interval must be a whole number of seconds inside the accepted
/// range; `null` and an absent field are equivalent.
fn interval<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    match Option::<Value>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Value::Number(value)) => {
            // JSON Schema integers include integral floating representations.
            let seconds = value
                .as_f64()
                .filter(|seconds| seconds.is_finite()
                    && *seconds >= 0.0
                    && *seconds <= MAX_INTERVAL as f64
                    && seconds.fract() == 0.0)
                .ok_or_else(|| serde::de::Error::custom("invalid polling interval"))?;
            Ok(Some(seconds as u64))
        }
        _ => Err(serde::de::Error::custom("invalid polling interval")),
    }
}

fn parse_input(input: &str) -> Result<Input, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid("electricity input exceeds its byte limit"));
    }
    let request: Input =
        serde_json::from_str(input).map_err(|_| invalid("invalid electricity input"))?;
    if !matches!(request.operation.as_str(), "resolve" | "balance") {
        return Err(invalid("operation must be resolve or balance"));
    }
    let usable = |value: &str| !value.is_empty() && value.chars().count() <= MAX_FIELD;
    let usable_selector = match &request.selector {
        MeterSelector::Identity(identity) => usable(&identity.identity_no),
        MeterSelector::Location(location) => [
            &location.campus,
            &location.building,
            &location.floor,
            &location.room,
        ]
        .into_iter()
        .all(|value| usable(value)),
    };
    if !usable_selector {
        return Err(invalid("selector values must contain 1 to 256 characters"));
    }
    if !request.authorization_confirmed {
        return Err(Error::new(
            "authorization_required",
            "authorization confirmation is required but cannot establish upstream permission",
        ));
    }
    if request
        .threshold_kwh
        .is_some_and(|value| !value.is_finite() || value < 0.0)
    {
        return Err(invalid("threshold_kwh must be a nonnegative finite number"));
    }
    if request
        .poll_interval_seconds
        .is_some_and(|seconds| seconds < MIN_POLL_SECONDS)
    {
        return Err(invalid("poll interval must be at least 900 seconds"));
    }
    Ok(request)
}

fn blocked(operation: &str, online: bool) -> Value {
    json!({"schema_version":1,"type":"electricity","operation":operation,"result":"blocked",
        "reason":"directory_authorization_and_raw_evidence_disclosure_conflict",
        "message":POLICY_MESSAGE,"online_requested":online,"network_requests":0,
        "https_probe":"not_performed_due_to_directory_privacy_blocker",
        "authorization":"caller_selector_is_not_identity_or_permission_proof",
        "unimplemented":["governed_https_probe","authorized_live_directory","live_balance",
            "background_observation_against_the_live_source"],
        "poll_floor_seconds":MIN_POLL_SECONDS,"background_floor_seconds":MIN_POLL_SECONDS,
        "cooldown_seconds":COOLDOWN_SECONDS,
        "persisted_state":"none_the_blocked_branch_writes_no_state",
        "next_step":"An independently authorized scoped meter source, or a reviewed privacy-safe probe contract, is required before any remote implementation can be enabled."})
}

/// Validate stdin and report the precise pre-request safety blocker. Neither
/// mode sends a request, opens the shared governor or writes any state at
/// all; selector values are never echoed, hashed, persisted or treated as
/// proof of permission. The separate observation API does keep local state,
/// and it keeps only what its caller supplied.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_input(input)?;
    Ok(blocked(&request.operation, online))
}

fn scalar(value: Option<&&RawValue>) -> Option<String> {
    let text = value?.get();
    match text.trim_start().as_bytes().first()? {
        b'"' => serde_json::from_str::<String>(text).ok(),
        b'-' | b'0'..=b'9' => serde_json::from_str::<serde_json::Number>(text)
            .ok()
            .map(|number| number.to_string()),
        _ => None,
    }
}

/// Select the single matching meter of a sanitized synthetic directory
/// fixture. This establishes no authorization and must not be fed a real full
/// directory for publication. Card numbers are never part of the projection.
pub fn parse_directory_fixture(
    bytes: &[u8],
    selector_json: &str,
) -> Result<Option<Value>, Error> {
    if bytes.len() > MAX_BODY || selector_json.len() > MAX_INPUT {
        return Err(invalid("fixture exceeds its byte limit"));
    }
    let selector: MeterSelector =
        serde_json::from_str(selector_json).map_err(|_| invalid("invalid fixture selector"))?;
    let rows: Vec<BTreeMap<String, &RawValue>> =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid directory fixture JSON"))?;
    if rows.len() > MAX_ENTRIES {
        return Err(invalid("directory fixture exceeds its entry limit"));
    }
    let mut selected = None;
    for row in rows {
        let entry = row;
        let id = scalar(entry.get("id")).ok_or_else(|| invalid("directory fixture entry lacks id"))?;
        if id.is_empty() || id.chars().count() > MAX_FIELD {
            return Err(invalid("invalid directory fixture entry"));
        }
        let matches = match &selector {
            MeterSelector::Identity(identity) => {
                scalar(entry.get("identityNo")).as_deref() == Some(identity.identity_no.as_str())
            }
            MeterSelector::Location(location) => {
                scalar(entry.get("campus")).as_deref() == Some(location.campus.as_str())
                    && scalar(entry.get("building")).as_deref() == Some(location.building.as_str())
                    && scalar(entry.get("floor")).as_deref() == Some(location.floor.as_str())
                    && scalar(entry.get("room")).as_deref() == Some(location.room.as_str())
            }
        };
        if matches {
            if selected.is_some() {
                return Err(invalid("ambiguous fixture selector"));
            }
            selected = Some(json!({
                "id": id,
                "name": scalar(entry.get("name")),
                "address": scalar(entry.get("address")),
                "meter_no": scalar(entry.get("meterNo")),
                "campus": scalar(entry.get("campus")),
                "building": scalar(entry.get("building")),
                "floor": scalar(entry.get("floor")),
                "room": scalar(entry.get("room")),
            }));
        }
    }
    Ok(selected)
}

// The shared governor already targets Linux, so the system converter supplies
// strict GBK decoding without a new Cargo dependency. A missing converter or
// an invalid sequence degrades the page; transliteration and replacement
// characters are never requested.
fn decode_gbk(bytes: &[u8]) -> Option<String> {
    let capacity = bytes.len().checked_mul(3)?.checked_add(4)?;
    let mut output = vec![0u8; capacity];
    // SAFETY: both encoding names are static NUL-terminated strings.
    let converter = unsafe { libc::iconv_open(c"UTF-8".as_ptr(), c"GBK".as_ptr()) };
    if converter == (-1isize) as libc::iconv_t {
        return None;
    }
    let mut input = bytes.as_ptr() as *mut libc::c_char;
    let mut input_left = bytes.len();
    let mut out = output.as_mut_ptr().cast::<libc::c_char>();
    let mut output_left = output.len();
    // SAFETY: the buffers cover the supplied lengths; iconv advances the
    // pointers without writing outside the output buffer.
    let result = unsafe {
        libc::iconv(
            converter,
            &mut input,
            &mut input_left,
            &mut out,
            &mut output_left,
        )
    };
    // SAFETY: the converter returned by iconv_open is closed exactly once.
    let closed = unsafe { libc::iconv_close(converter) };
    if result != 0 || input_left != 0 || closed != 0 {
        return None;
    }
    output.truncate(capacity - output_left);
    String::from_utf8(output).ok()
}

fn charset(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => Some("utf-8"),
        "gbk" | "gb2312" | "x-gbk" | "gb_2312-80" => Some("gbk"),
        _ => None,
    }
}

fn admit_charset(selected: &mut Option<&'static str>, value: &str) -> Result<(), &'static str> {
    let encoding = charset(value).ok_or("unsupported_charset")?;
    if selected.is_some_and(|previous| previous != encoding) {
        return Err("unsupported_charset");
    }
    *selected = Some(encoding);
    Ok(())
}

fn mime_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
                | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
    })
}

/// Parse complete MIME parameters, so a quoted semicolon cannot introduce a
/// fake charset. A valid content type need not declare a charset at all.
fn charset_parameters(
    value: &str,
    selected: &mut Option<&'static str>,
    charset_only: bool,
    html_meta: bool,
) -> Result<(), &'static str> {
    let Some((_, mut parameters)) = value.split_once(';') else { return Ok(()) };
    loop {
        let trimmed = parameters.trim_start();
        if trimmed.is_empty() { return Err("unsupported_charset"); }
        let equal = trimmed.find('=').ok_or("unsupported_charset")?;
        let name = trimmed[..equal].trim();
        if !mime_token(name) || (charset_only && !name.eq_ignore_ascii_case("charset")) {
            return Err("unsupported_charset");
        }
        let rest = trimmed[equal + 1..].trim_start();
        let (parameter, tail, quoted) = if let Some(quoted) = rest.strip_prefix('"') {
            let mut escaped = false;
            let mut closing = None;
            for (index, byte) in quoted.bytes().enumerate() {
                if byte < 0x20 || byte == 0x7f { return Err("unsupported_charset"); }
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    closing = Some(index);
                    break;
                }
            }
            let end = closing.ok_or("unsupported_charset")?;
            let parameter = &quoted[..end];
            let parameter = if parameter.contains('\\') {
                let mut unescaped = String::with_capacity(parameter.len());
                let mut chars = parameter.chars();
                while let Some(ch) = chars.next() {
                    unescaped.push(if ch == '\\' {
                        chars.next().ok_or("unsupported_charset")?
                    } else { ch });
                }
                std::borrow::Cow::Owned(unescaped)
            } else {
                std::borrow::Cow::Borrowed(parameter)
            };
            (parameter, &quoted[end + 1..], true)
        } else {
            let end = rest.find(';').unwrap_or(rest.len());
            let parameter = rest[..end].trim();
            if !mime_token(parameter) { return Err("unsupported_charset"); }
            (std::borrow::Cow::Borrowed(parameter), &rest[end..], false)
        };
        if name.eq_ignore_ascii_case("charset") {
            // HTML's legacy meta content syntax also permits single quotes
            // around the label; MIME header parameters do not use them.
            let label: &str = if html_meta && !quoted && parameter.starts_with('\'') {
                parameter.strip_prefix('\'').and_then(|label| label.strip_suffix('\''))
                    .ok_or("unsupported_charset")?
            } else {
                &parameter
            };
            admit_charset(selected, label)?;
        }
        let tail = tail.trim_start();
        match tail.strip_prefix(';') {
            Some(rest) => parameters = rest,
            None if tail.is_empty() => return Ok(()),
            None => return Err("unsupported_charset"),
        }
    }
}

fn declared_charset(
    content_type: Option<&str>,
    bytes: &[u8],
) -> Result<Option<&'static str>, &'static str> {
    let mut selected = None;
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        admit_charset(&mut selected, "utf-8")?;
    }
    if let Some(header) = content_type {
        let mime = header.split(';').next().unwrap_or("").trim();
        if !mime.eq_ignore_ascii_case("text/html")
            && !mime.eq_ignore_ascii_case("application/xhtml+xml")
        {
            return Err("unexpected_content_type");
        }
        charset_parameters(header, &mut selected, false, false)?;
    }
    // A meta declaration is ASCII in both supported encodings.
    let prefix: String = bytes
        .iter()
        .map(|byte| if byte.is_ascii() { *byte as char } else { ' ' })
        .collect();
    let doc = Html::parse_document(&prefix);
    let metas = Selector::parse("meta").map_err(|_| "internal_selector")?;
    for meta in doc.select(&metas).filter(|element| !inert_element(*element)) {
        if let Some(value) = meta.value().attr("charset") {
            admit_charset(&mut selected, value.trim())?;
        }
        if meta.value().attr("http-equiv").is_some_and(|value| {
            value.trim().eq_ignore_ascii_case("Content-Type")
        }) {
            let content = meta.value().attr("content").ok_or("unsupported_charset")?;
            let mime = content.split(';').next().unwrap_or("").trim();
            if !mime.eq_ignore_ascii_case("text/html") {
                return Err("unsupported_charset");
            }
            charset_parameters(content, &mut selected, false, true)?;
        }
    }
    Ok(selected)
}

fn decode_html(
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<(String, &'static str), &'static str> {
    let declared = declared_charset(content_type, bytes)?;
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    match declared {
        Some("gbk") => decode_gbk(bytes)
            .map(|text| (text, "gbk"))
            .ok_or("charset_decode_failed"),
        Some("utf-8") => std::str::from_utf8(bytes)
            .map(|text| (text.to_owned(), "utf-8"))
            .map_err(|_| "charset_decode_failed"),
        _ => match std::str::from_utf8(bytes) {
            Ok(text) => Ok((text.to_owned(), "utf-8")),
            Err(_) => decode_gbk(bytes)
                .map(|text| (text, "gbk"))
                .ok_or("charset_decode_failed"),
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    Ident,
    Number,
    Str,
    Punct(u8),
}

#[derive(Clone, Copy, Debug)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

/// ECMAScript line terminators, including those HTML does not normalize.
fn script_line_terminator(bytes: &[u8], offset: usize) -> bool {
    matches!(bytes.get(offset), Some(b'\n' | b'\r'))
        || bytes[offset..].starts_with(b"\xe2\x80\xa8")
        || bytes[offset..].starts_with(b"\xe2\x80\xa9")
}

/// Non-executing lexer: strings and comments are opaque. Non-comment slash
/// syntax is unsupported rather than risking scanning a regex as members.
fn tokenize(script: &str) -> Result<Vec<Token>, &'static str> {
    let bytes = script.as_bytes();
    let mut tokens: Vec<Token> = Vec::new();
    let mut offset = 0usize;
    let mut line_has_code = false;
    while offset < bytes.len() {
        if bytes[offset..].starts_with(b"\xe2\x80\xa8")
            || bytes[offset..].starts_with(b"\xe2\x80\xa9")
        {
            offset += 3;
            line_has_code = false;
            continue;
        }
        if bytes[offset].is_ascii_whitespace() {
            if script_line_terminator(bytes, offset) { line_has_code = false; }
            offset += 1;
            continue;
        }
        // Annex B classic-script comments are opaque through the line end.
        if bytes[offset..].starts_with(b"<!--")
            || (bytes[offset..].starts_with(b"-->") && !line_has_code)
        {
            while offset < bytes.len() && !script_line_terminator(bytes, offset) {
                offset += 1;
            }
            continue;
        }
        let byte = bytes[offset];
        if byte != b'/' { line_has_code = true; }
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' => offset += 1,
            b'"' | b'\'' => {
                let start = offset;
                offset += 1;
                let mut closed = false;
                while let Some(&next) = bytes.get(offset) {
                    offset += 1;
                    if next == byte {
                        closed = true;
                        break;
                    }
                    if matches!(next, b'\n' | b'\r') {
                        return Err("unterminated_string");
                    }
                    if next == b'\\' {
                        offset += 1;
                        if bytes.get(offset).is_none() {
                            return Err("unterminated_string");
                        }
                    }
                }
                if !closed {
                    return Err("unterminated_string");
                }
                tokens.push(Token {
                    kind: TokenKind::Str,
                    start,
                    end: offset,
                });
            }
            b'`' => return Err("unsupported_script_syntax"),
            b'\\' => return Err("unsupported_script_syntax"),
            b'/' => match bytes.get(offset + 1) {
                Some(b'/') => {
                    while offset < bytes.len() && !script_line_terminator(bytes, offset) {
                        offset += 1;
                    }
                }
                Some(b'*') => {
                    offset += 2;
                    let mut closed = false;
                    while offset + 1 < bytes.len() {
                        if script_line_terminator(bytes, offset) { line_has_code = false; }
                        if bytes[offset] == b'*' && bytes[offset + 1] == b'/' {
                            offset += 2;
                            closed = true;
                            break;
                        }
                        offset += 1;
                    }
                    if !closed {
                        return Err("unterminated_comment");
                    }
                }
                _ => {
                    // Slash goal depends on the complete JavaScript grammar.
                    // Neither division nor regex is part of this literal-only
                    // contract: never scan a regex payload as source members.
                    return Err("unsupported_script_syntax");
                }
            },
            b'0'..=b'9' => {
                let start = offset;
                offset += 1;
                while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
                    offset += 1;
                }
                if bytes.get(offset) == Some(&b'.')
                    && bytes.get(offset + 1).is_some_and(u8::is_ascii_digit)
                {
                    offset += 1;
                    while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
                        offset += 1;
                    }
                }
                if matches!(bytes.get(offset), Some(b'e') | Some(b'E')) {
                    let mut cursor = offset + 1;
                    if matches!(bytes.get(cursor), Some(b'+') | Some(b'-')) {
                        cursor += 1;
                    }
                    if bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                            cursor += 1;
                        }
                        offset = cursor;
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Number,
                    start,
                    end: offset,
                });
            }
            _ if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') => {
                let start = offset;
                offset += 1;
                while bytes.get(offset).is_some_and(|value| {
                    value.is_ascii_alphanumeric() || matches!(value, b'_' | b'$')
                }) {
                    offset += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Ident,
                    start,
                    end: offset,
                });
            }
            byte if byte < 0x80 => {
                tokens.push(Token {
                    kind: TokenKind::Punct(byte),
                    start: offset,
                    end: offset + 1,
                });
                offset += 1;
            }
            _ => return Err("unsupported_script_syntax"),
        }
    }
    Ok(tokens)
}

/// The member name `data`, written either as an identifier or as a quoted
/// object key.
fn is_data_member(script: &str, token: Token) -> bool {
    let text = &script.as_bytes()[token.start..token.end];
    match token.kind {
        TokenKind::Ident => text == b"data",
        TokenKind::Str => text == b"\"data\"" || text == b"'data'",
        _ => false,
    }
}

/// The chart declaration binds one array of category strings to one array of
/// usage numbers. Both arrays are the values of an object member literally
/// named `data`, so a `data` inside a string, a comment, an array element or a
/// statement label can never supply a value.
/// Computed object keys and object spread are unsupported: they may supply
/// or override data, so they refuse the declaration rather than disappearing
/// from the page's uniqueness decision. Ordinary array expressions are not
/// computed members unless they occupy an object-member position.
///
/// `Ok(None)` means the script owns no `data` array and is therefore not a
/// chart candidate. `Err` means it owns one whose count or element shape does
/// not match the contract, which is reported for review instead of being
/// reinterpreted.
fn script_history(script: &str) -> Result<Option<(Value, Value)>, &'static str> {
    if script.len() > MAX_SCRIPT_TEXT {
        return Err("script_text_limit");
    }
    // Unsupported syntax cannot establish uniqueness of a chart declaration.
    let tokens = tokenize(script).map_err(|_| "script_unlexable")?;
    // Admit object literals in assignments and object-member values only.
    // A bare `{` starts a statement block, not an object declaration. Other
    // expression contexts are deliberately unsupported, never reinterpreted.
    let mut containers: Vec<(u8, bool)> = Vec::new();
    let mut object_members = Vec::with_capacity(tokens.len());
    for (position, token) in tokens.iter().enumerate() {
        if token.kind == TokenKind::Str
            && script[token.start..token.end].contains('\\')
            && tokens.get(position + 1)
                .is_some_and(|next| next.kind == TokenKind::Punct(b':'))
        {
            return Err("script_unlexable");
        }
        let in_object = containers.last() == Some(&(b'{', true));
        let member_start = containers.last().is_some_and(|entry| entry.0 == b'{')
            && position > 0
            && matches!(tokens[position - 1].kind, TokenKind::Punct(b'{' | b','));
        if member_start && token.kind == TokenKind::Punct(b'.')
            && tokens.get(position + 1).is_some_and(|next| next.kind == TokenKind::Punct(b'.'))
            && tokens.get(position + 2).is_some_and(|next| next.kind == TokenKind::Punct(b'.'))
        {
            // Spread can supply or overwrite data, including a previously
            // admitted literal. Its absence cannot be established statically.
            return Err("script_unlexable");
        }
        if member_start && token.kind == TokenKind::Punct(b'[') {
            if in_object {
                return Err("script_unlexable");
            }
            // In an unsupported brace context, distinguish a computed member
            // from a normal array-expression statement by its following colon.
            let mut brackets = 0usize;
            for (end, next) in tokens.iter().enumerate().skip(position) {
                match next.kind {
                    TokenKind::Punct(b'[') => brackets += 1,
                    TokenKind::Punct(b']') => {
                        brackets -= 1;
                        if brackets == 0 {
                            if tokens.get(end + 1)
                                .is_some_and(|after| after.kind == TokenKind::Punct(b':'))
                            {
                                return Err("script_unlexable");
                            }
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        // A data-shaped label in a block or an unsupported expression brace
        // cannot establish absence of another chart. Refuse rather than
        // silently dropping the declaration (e.g. y=({data:...})).
        if containers.last() == Some(&(b'{', false))
            && is_data_member(script, *token)
            && tokens.get(position + 1)
                .is_some_and(|next| next.kind == TokenKind::Punct(b':'))
        {
            return Err("script_unlexable");
        }
        object_members.push(in_object);
        let previous = position.checked_sub(1).map(|index| tokens[index].kind);
        match token.kind {
            TokenKind::Punct(b'{') => {
                let assignment = matches!(previous, Some(TokenKind::Punct(b'=')))
                    && position >= 2
                    && !matches!(tokens[position - 2].kind,
                        TokenKind::Punct(b'=' | b'!' | b'<' | b'>'));
                let member_value = in_object
                    && matches!(previous, Some(TokenKind::Punct(b':')))
                    && position >= 3
                    && matches!(tokens[position - 2].kind, TokenKind::Ident | TokenKind::Str)
                    && matches!(tokens[position - 3].kind, TokenKind::Punct(b'{' | b','));
                let object = assignment || member_value;
                containers.push((b'{', object));
            }
            TokenKind::Punct(open @ (b'[' | b'(')) => containers.push((open, false)),
            TokenKind::Punct(close @ (b'}' | b']' | b')')) => {
                let expected = match close { b'}' => b'{', b']' => b'[', _ => b'(' };
                if containers.pop().map(|entry| entry.0) != Some(expected) {
                    return Err("script_unlexable");
                }
            }
            _ => {}
        }
    }
    if !containers.is_empty() {
        return Err("script_unlexable");
    }
    let mut arrays = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        if object_members[index]
            && is_data_member(script, tokens[index])
            && index > 0
            && matches!(tokens[index - 1].kind, TokenKind::Punct(b'{' | b','))
            && tokens.get(index + 1).is_some_and(|token| token.kind == TokenKind::Punct(b':'))
            && !tokens.get(index + 2).is_some_and(|token| token.kind == TokenKind::Punct(b'['))
        {
            return Err("history_ambiguous");
        }
        let owns_member = object_members[index]
            && is_data_member(script, tokens[index])
            && tokens
                .get(index + 1)
                .is_some_and(|token| token.kind == TokenKind::Punct(b':'))
            && index > 0
            && matches!(
                tokens[index - 1].kind,
                TokenKind::Punct(b'{') | TokenKind::Punct(b',')
            )
            && tokens
                .get(index + 2)
                .is_some_and(|token| token.kind == TokenKind::Punct(b'['));
        if !owns_member {
            index += 1;
            continue;
        }
        let open = tokens[index + 2].start;
        let mut depth = 0usize;
        let mut cursor = index + 2;
        let mut close = None;
        while cursor < tokens.len() {
            match tokens[cursor].kind {
                TokenKind::Punct(b'[') => depth += 1,
                TokenKind::Punct(b']') => {
                    depth = depth.checked_sub(1).ok_or("history_ambiguous")?;
                    if depth == 0 {
                        close = Some(tokens[cursor].end);
                        break;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        let Some(close) = close else {
            return Err("history_ambiguous");
        };
        if !tokens.get(cursor + 1).is_some_and(|token| {
            matches!(token.kind, TokenKind::Punct(b',') | TokenKind::Punct(b'}'))
        }) {
            return Err("history_ambiguous");
        }
        let text = std::str::from_utf8(&script.as_bytes()[open..close])
            .map_err(|_| "history_ambiguous")?;
        arrays.push(text);
        index += 3;
    }
    if arrays.is_empty() {
        return Ok(None);
    }
    if arrays.len() != 2 {
        return Err("history_ambiguous");
    }
    let dates: Vec<String> = serde_json::from_str(arrays[0]).map_err(|_| "history_ambiguous")?;
    let usage: Vec<serde_json::Number> =
        serde_json::from_str(arrays[1]).map_err(|_| "history_ambiguous")?;
    if dates.is_empty() || dates.len() > MAX_ARRAY_ITEMS || usage.len() > MAX_ARRAY_ITEMS {
        return Err("history_ambiguous");
    }
    if usage.len() < dates.len() {
        return Err("history_ambiguous");
    }
    if dates
        .iter()
        .any(|text| text.is_empty())
    {
        return Err("history_ambiguous");
    }
    if usage
        .iter()
        .any(|value| !value.as_f64().is_some_and(|number| number.is_finite()))
    {
        return Err("history_ambiguous");
    }
    Ok(Some((
        Value::Array(dates.into_iter().map(Value::String).collect()),
        Value::Array(usage.into_iter().map(Value::Number).collect()),
    )))
}

fn parse_number(text: &str) -> Option<f64> {
    let text = text.trim();
    let text = text
        .strip_suffix("kWh")
        .or_else(|| text.strip_suffix('度'))
        .unwrap_or(text)
        .trim();
    let value: f64 = text.parse().ok()?;
    value.is_finite().then_some(value)
}

/// Read the balance readings from active leaf tspan elements. Ancestors of
/// another active tspan cannot count that descendant's text a second time.
/// Every numeric leaf token is a candidate, so an extra candidate leaves the
/// intended pair ambiguous and the page degrades instead of shifting values.
/// A tspan that carries no number is a label, not a reading.
fn balance_readings(document: &Html) -> Result<(f64, f64), &'static str> {
    let spans = Selector::parse("tspan").map_err(|_| "internal_selector")?;
    let mut readings: Vec<f64> = Vec::new();
    for span in document.select(&spans).filter(|element| !inert_element(*element)) {
        if span.select(&spans).any(|child| !inert_element(child)) {
            continue;
        }
        for token in element_text(span).split_whitespace() {
            if let Some(value) = parse_number(token) {
                readings.push(value);
            }
        }
    }
    if readings.is_empty() {
        return Err("balance_values_missing");
    }
    if readings.len() != 2 {
        return Err("balance_values_ambiguous");
    }
    Ok((readings[0], readings[1]))
}

/// Read the room name and address from the floated container. The room name
/// is the first direct `p.shadow` child and the address is the last
/// `p.shadow` of that container whose documented `地址:` prefix is removed.
/// A container whose first child is itself an address line, or that carries
/// no address line at all, is not a match.
fn room_and_address(document: &Html) -> Result<(String, String), &'static str> {
    let divs = Selector::parse("div").map_err(|_| "internal_selector")?;
    let children = Selector::parse(":scope > p.shadow").map_err(|_| "internal_selector")?;
    let descendants = Selector::parse("p.shadow").map_err(|_| "internal_selector")?;
    for div in document.select(&divs).filter(|element| !inert_element(*element)) {
        let style = div.value().attr("style").unwrap_or("");
        let floated = style.split(';').any(|declaration| {
            declaration
                .split(':')
                .map(str::trim)
                .eq(["float", "left"].into_iter())
        });
        if !floated {
            continue;
        }
        let texts = |selector: &Selector| -> Vec<String> {
            div.select(selector)
            .filter(|element| !inert_element(*element))
            .map(element_text)
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
                .collect()
        };
        let Some(room) = texts(&children).into_iter().next() else {
            continue;
        };
        if is_address_line(&room) {
            continue;
        }
        let Some(address) = texts(&descendants)
            .into_iter()
            .rev()
            .find_map(|text| address_line(&text))
        else {
            continue;
        };
        return Ok((room, address));
    }
    Err("room_address_missing")
}

fn is_address_line(text: &str) -> bool {
    text.starts_with("地址:") || text.starts_with("地址：")
}

fn address_line(text: &str) -> Option<String> {
    let rest = text.strip_prefix("地址:").or_else(|| text.strip_prefix("地址："))?;
    let address = rest.trim();
    (!address.is_empty()).then(|| address.to_owned())
}

/// Read the recharge rows of the table bodies. A body without rows keeps its
/// text as one unstructured record instead of losing it.
fn recharge_records(document: &Html) -> Result<Vec<Value>, &'static str> {
    let bodies = Selector::parse("tbody").map_err(|_| "internal_selector")?;
    let rows = Selector::parse("tr").map_err(|_| "internal_selector")?;
    let cells = Selector::parse(":scope > td, :scope > th").map_err(|_| "internal_selector")?;
    let mut records = Vec::new();
    let mut found = false;
    for body in document
        .select(&bodies)
        .filter(|element| !inert_element(*element))
    {
        found = true;
        let mut body_records = Vec::new();
        for row in body.select(&rows).filter(|element| !inert_element(*element)) {
            let values: Vec<String> = row
                .select(&cells)
                .filter(|element| !inert_element(*element))
                .map(element_text)
                .collect();
            if !values.is_empty() {
                body_records.push(json!({ "cells": values }));
            }
        }
        if body_records.is_empty() {
            let text = element_text(body);
            if !text.trim().is_empty() {
                body_records.push(json!({ "text": text.trim() }));
            }
        }
        records.extend(body_records);
    }
    if !found {
        return Err("recharge_records_missing");
    }
    Ok(records)
}

/// The chart history of the page. Only an active HTML classic inline script can
/// declare it: an external script body, a `text/plain` payload and an inert
/// template body are not active source.
fn chart_history(document: &Html) -> Result<(Value, Value), &'static str> {
    let scripts = Selector::parse("script").map_err(|_| "internal_selector")?;
    let mut declared = 0usize;
    let mut selected: Option<Result<(Value, Value), &'static str>> = None;
    let mut unlexable = false;
    for script in document
        .select(&scripts)
        .filter(|element| !inert_element(*element))
    {
        // This parser's source contract is HTML classic inline scripts only.
        // SVG script href/xlink:href bodies must never contribute history.
        if !crate::html::is_html_element(script)
            || script.value().attr("src").is_some()
        {
            continue;
        }
        if script_kind(script) != Some(ScriptKind::Classic) {
            continue;
        }
        let text: String = script.text().collect::<Vec<_>>().concat();
        match script_history(&text) {
            Ok(Some(pair)) => {
                declared += 1;
                selected = Some(Ok(pair));
            }
            // A script that owns no `data` array cannot declare the chart.
            Ok(None) => {}
            // This active script cannot be inspected: its
            // potential competing declaration must not disappear.
            Err("script_unlexable") => unlexable = true,
            Err(reason) => {
                declared += 1;
                selected = Some(Err(reason));
            }
        }
    }
    if unlexable {
        return Err("script_unlexable");
    }
    if declared > 1 {
        return Err("history_ambiguous");
    }
    match selected {
        Some(result) => result,
        None => Err("history_missing"),
    }
}

/// Parse one balance page. Every branch either returns the full structured
/// reading or a precise failure reason for degradation.
pub fn parse_balance_page(bytes: &[u8], content_type: Option<&str>) -> Result<Value, &'static str> {
    if bytes.len() > MAX_BODY {
        return Err("body_limit");
    }
    if response_withholding(bytes, content_type).is_some() {
        return Err("response_withheld");
    }
    let (text, encoding) = decode_html(bytes, content_type)?;
    let document = Html::parse_document(&text);
    let (remaining, yesterday) = balance_readings(&document)?;
    let (room, address) = room_and_address(&document)?;
    let records = recharge_records(&document)?;
    let (dates, usage) = chart_history(&document)?;
    Ok(json!({
        "remaining_kwh": remaining,
        "yesterday_usage_kwh": yesterday,
        "room": room,
        "address": address,
        "recharge_records": records,
        "history": {"dates": dates, "usage_kwh": usage},
        "charset": encoding,
    }))
}

fn marked_bytes(bytes: &[u8]) -> bool {
    ["password", "passwd", "pwd", "credential", "cookie", "authorization",
        "bearer", "ticket", "nonce", "jwt", "secret", "session", "token",
        "csrf", "xsrf", "execution", "username", "user_name", "loginname", "login_name",
        "one-time-code", "captcha", "challenge", "turnstile", "verification_code",
        "密码", "口令", "验证码", "校验码", "用户名", "\\u", "\\x", "&#"]
        .iter().any(|marker| {
            let marker = marker.as_bytes();
            bytes.windows(marker.len()).any(|part| part.eq_ignore_ascii_case(marker))
        })
}

fn percent_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn has_percent_escape(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|part| {
        part[0] == b'%' && percent_digit(part[1]).is_some() && percent_digit(part[2]).is_some()
    })
}

/// Decode a form component as bytes, not lossy UTF-8: a GBK-encoded name can
/// occur alongside already-decoded UTF-8 text in the same component.
fn decode_percent_component(bytes: &[u8]) -> Option<Vec<u8>> {
    if !has_percent_escape(bytes) { return None; }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (percent_digit(bytes[index + 1]), percent_digit(bytes[index + 2])) {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(if bytes[index] == b'+' { b' ' } else { bytes[index] });
        index += 1;
    }
    Some(decoded)
}

fn gbk_private_labels(bytes: &[u8]) -> bool {
    // GBK byte spellings of the same Chinese labels in marked_bytes. Search
    // the decoded component directly rather than converting a mixed-encoding
    // component, which could lose or misinterpret an adjacent label.
    [b"\xc3\xdc\xc2\xeb".as_slice(), b"\xbf\xda\xc1\xee",
        b"\xd3\xc3\xbb\xa7\xc3\xfb", b"\xd1\xe9\xd6\xa4\xc2\xeb",
        b"\xd0\xa3\xd1\xe9\xc2\xeb"]
        .iter().any(|marker| bytes.windows(marker.len()).any(|part| part == *marker))
}

/// Scan the original source and decoded form components without treating a
/// literal percent as private. Nested encodings are bounded; a deeper encoding
/// is unreviewed rather than silently admitted or called a credential.
fn private_markers(text: &str) -> Result<bool, ()> {
    if marked_bytes(text.as_bytes()) { return Ok(true); }
    if !text.as_bytes().contains(&b'%') { return Ok(false); }
    for component in text.split(['&', '=']) {
        let mut current = std::borrow::Cow::Borrowed(component.as_bytes());
        for _ in 0..8 {
            let Some(decoded) = decode_percent_component(&current) else { break };
            if marked_bytes(&decoded) || gbk_private_labels(&decoded) { return Ok(true); }
            current = std::borrow::Cow::Owned(decoded);
        }
        if has_percent_escape(&current) { return Err(()); }
    }
    Ok(false)
}

fn marker_withholding(text: &str) -> Option<&'static str> {
    match private_markers(text) {
        Ok(true) => Some("sensitive_response_material"),
        Ok(false) => None,
        Err(()) => Some("response_safety_unreviewed"),
    }
}

/// A control can contain private values even when its name is unfamiliar,
/// disabled, hidden or inside an inert template. Privacy scans therefore use
/// the whole source tree rather than the active business projection.
fn document_privacy_reason(text: &str) -> Option<&'static str> {
    let document = Html::parse_document(text);
    let mut projection = String::new();
    let mut unreviewed_fallback = false;
    for node in document.tree.root().descendants() {
        match node.value() {
            Node::Text(text) => {
                projection.extend(text.text.chars().filter(|character| !character.is_whitespace()));
            }
            Node::Element(element) => {
                let Some(reference) = ElementRef::wrap(node) else { continue };
                if crate::html::is_html_element(reference) && element.name() == "noscript"
                    && reference.text().any(|value| !value.trim().is_empty())
                {
                    // With scripting enabled, noscript fallback is raw text,
                    // not a reviewed tree of controls.
                    unreviewed_fallback = true;
                }
                if matches!(element.name(), "input" | "button" | "select" | "option" | "textarea")
                    && (element.attr("value").is_some()
                        || (matches!(element.name(), "textarea" | "option")
                            && reference.text().any(|value| !value.trim().is_empty())))
                {
                    return Some("sensitive_response_material");
                }
                for (name, value) in element.attrs() {
                    let joined: String = name.chars().chain(value.chars())
                        .filter(|character| !character.is_whitespace()).collect();
                    if let Some(reason) = marker_withholding(&joined) { return Some(reason); }
                }
            }
            _ => {}
        }
    }
    if let Some(reason) = marker_withholding(&projection) { return Some(reason); }
    unreviewed_fallback.then_some("response_safety_unreviewed")
}

fn safe_content_type(value: Option<&str>) -> Option<&str> {
    let value = value?;
    let mime = value.split(';').next()?.trim();
    if !["text/html", "application/xhtml+xml", "application/json", "text/plain"]
        .iter().any(|allowed| mime.eq_ignore_ascii_case(allowed))
        || value.chars().any(char::is_control)
    { return None; }
    charset_parameters(value, &mut None, true, false).ok()?;
    Some(value)
}

fn response_withholding(bytes: &[u8], content_type: Option<&str>) -> Option<&'static str> {
    if content_type.is_some() && safe_content_type(content_type).is_none() {
        return Some("unsafe_response_metadata");
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok() {
            // Inspect every decoded string token, including duplicate keys
            // that converting the document into a Value map would discard.
            let tokens = match tokenize(text) {
                Ok(tokens) => tokens,
                Err(_) => return Some("response_safety_unreviewed"),
            };
            for token in tokens.iter().filter(|token| token.kind == TokenKind::Str) {
                let decoded = match serde_json::from_str::<String>(&text[token.start..token.end]) {
                    Ok(decoded) => decoded,
                    Err(_) => return Some("response_safety_unreviewed"),
                };
                if let Some(reason) = marker_withholding(&decoded) { return Some(reason); }
            }
            return None;
        }
        if let Some(reason) = marker_withholding(text) { return Some(reason); }
    }
    let text = match decode_html(bytes, content_type) {
        Ok((text, _)) => text,
        Err(_) => return Some("response_safety_unreviewed"),
    };
    if let Some(reason) = marker_withholding(&text) { return Some(reason); }
    match crate::html::assess_challenge_body(text.as_bytes(), Some("text/html; charset=utf-8"), true) {
        crate::html::ChallengeAssessment::Clear => document_privacy_reason(&text),
        crate::html::ChallengeAssessment::Detected => Some("challenge_detected"),
        crate::html::ChallengeAssessment::Unreviewed => Some("response_safety_unreviewed"),
    }
}

/// Parse supplied balance bytes without I/O. Only reviewed-safe bodies retain
/// exact originals for offline recovery. Credentials, challenges, unsafe
/// metadata and unreviewable bodies retain length/digest but withhold bytes;
/// a fixture label does not make arbitrary caller bytes safe for logging.
pub fn parse_balance_fixture(bytes: &[u8], content_type: Option<&str>) -> Result<Value, Error> {
    if bytes.len() > MAX_BODY {
        return Err(invalid("balance fixture exceeds its byte limit"));
    }
    if let Some(reason) = response_withholding(bytes, content_type) {
        return Ok(json!({"result":"degraded","balance":null,"raw_evidence":{
            "encoding":"base64","data":null,"content_type":safe_content_type(content_type),
            "byte_length":bytes.len(),"sha256":digest(bytes),"fallback_reason":reason,
            "raw_withheld":true,"raw_withheld_reason":reason,
            "content_type_parameters_withheld":content_type.is_some() && safe_content_type(content_type).is_none()}}));
    }
    match parse_balance_page(bytes, content_type) {
        Ok(balance) => Ok(json!({"result":"parsed","balance":balance,"raw_evidence":null})),
        Err(reason) => Ok(json!({"result":"degraded","balance":null,"raw_evidence":{
            "encoding":"base64","data":STANDARD.encode(bytes),"content_type":content_type,
            "byte_length":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),
            "fallback_reason":reason,"raw_withheld":false,"raw_withheld_reason":null,
            "content_type_parameters_withheld":false}})),
    }
}

/// Re-read the exact bytes of a degraded evidence envelope offline. The
/// envelope is self-verifying: the declared length and digest must match the
/// stored bytes, so a truncated or edited evidence object is refused instead
/// of being re-parsed as if it were the original response.
pub fn restore_raw_evidence(evidence: &Value) -> Result<(Vec<u8>, Option<String>), Error> {
    if evidence.get("raw_withheld").and_then(Value::as_bool) == Some(true) {
        return Err(invalid("withheld evidence has no recoverable payload"));
    }
    if evidence.get("encoding").and_then(Value::as_str) != Some("base64") {
        return Err(invalid("evidence is not a base64 envelope"));
    }
    let data = evidence
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("evidence lacks its base64 payload"))?;
    let bytes = STANDARD
        .decode(data)
        .map_err(|_| invalid("evidence base64 payload is invalid"))?;
    let content_type = match evidence.get("content_type") {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Null) | None => None,
        Some(_) => return Err(invalid("evidence content type is invalid")),
    };
    if evidence.get("byte_length").and_then(Value::as_u64) != Some(bytes.len() as u64) {
        return Err(invalid("evidence byte length does not match its payload"));
    }
    let expected = digest(&bytes);
    if evidence.get("sha256").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err(invalid("evidence digest does not match its payload"));
    }
    if response_withholding(&bytes, content_type.as_deref()).is_some() {
        return Err(invalid("evidence payload is not admitted for disclosure"));
    }
    Ok((bytes, content_type))
}

/// Pure edge-triggered transition calculation. The first observation and a
/// changed threshold establish a baseline; only a crossing produces a
/// transition, and a transition inside the cooldown window is suppressed.
pub fn threshold_transition(
    previous: Option<f64>,
    current: f64,
    limit: f64,
    last_notified_at_unix_ms: Option<u64>,
    now_unix_ms: u64,
) -> Result<Value, Error> {
    if !current.is_finite() || !limit.is_finite() || limit < 0.0 {
        return Err(invalid(
            "threshold observations must be finite and the threshold nonnegative",
        ));
    }
    if previous.is_some_and(|value| !value.is_finite()) {
        return Err(invalid("threshold observations must be finite"));
    }
    let transition = previous.and_then(|old| {
        if old > limit && current <= limit {
            Some("below_threshold")
        } else if old <= limit && current > limit {
            Some("above_threshold")
        } else {
            None
        }
    });
    let suppressed = transition.is_some()
        && last_notified_at_unix_ms
            .is_some_and(|last| now_unix_ms.saturating_sub(last) < COOLDOWN_SECONDS * 1000);
    Ok(json!({
        "threshold_kwh": limit,
        "previous_balance_kwh": previous,
        "current_balance_kwh": current,
        "transition": transition,
        "notified": transition.is_some() && !suppressed,
        "cooldown_suppressed": suppressed,
        "cooldown_seconds": COOLDOWN_SECONDS,
    }))
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    version: u8,
    last_balance_kwh: Option<f64>,
    threshold_kwh: Option<f64>,
    last_notified_at_unix_ms: Option<u64>,
    last_background_at_unix_ms: Option<u64>,
}

struct Store {
    directory: File,
}

/// A per-key local lock over one observation state file.
///
/// The lock file is created once and never replaced, so every process that
/// observes the same key locks the same inode. It is a private regular file:
/// owned by this account, mode 0600, a single link and opened without
/// following symlinks. The guard covers the whole read, transition and write
/// of one observation, so a crossing is evaluated once and the polling window
/// cannot be lost by a concurrent writer.
///
/// This lock synchronizes the local private cache only. It is not the shared
/// request governor, it authorizes nothing and it never talks to the network.
struct KeyLock {
    file: File,
}

impl KeyLock {
    fn acquire(directory: &File, key: &str) -> Result<Self, Error> {
        let name = Store::lock_name(key);
        let file = match governor::open_child(
            directory,
            &name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => {
                // SAFETY: the descriptor was created exclusively by this call.
                if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                    return Err(local_error());
                }
                file
            }
            // The lock file already exists. It keeps its inode, so every
            // later observation locks the same object.
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => {
                governor::open_child(directory, &name, libc::O_RDWR).map_err(|_| local_error())?
            }
            Err(_) => return Err(local_error()),
        };
        governor::validate_private_file(&file).map_err(|_| local_error())?;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(LOCK_TIMEOUT_SECONDS);
        loop {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self { file }),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(Error::new(
                            "local_state_lock_timeout",
                            "the private observation state of this key is busy",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(LOCK_POLL_MILLIS));
                }
                Err(_) => return Err(local_error()),
            }
        }
    }
}

impl Drop for KeyLock {
    fn drop(&mut self) {
        // Closing the descriptor releases the lock even if the unlock fails.
        let _ = FileExt::unlock(&self.file);
    }
}

impl Store {
    fn open() -> Result<Self, Error> {
        let home = governor::identity_home().map_err(|_| local_error())?;
        let _home = governor::open_directory(&home, false, false).map_err(|_| local_error())?;
        let directory =
            governor::open_directory(&home.join(PRIVATE_DIR), true, true).map_err(|_| local_error())?;
        Ok(Self { directory })
    }

    #[cfg(test)]
    fn open_at(path: &std::path::Path) -> Result<Self, Error> {
        let directory =
            governor::open_directory(path, true, true).map_err(|_| local_error())?;
        Ok(Self { directory })
    }

    fn validate(&self) -> Result<(), Error> {
        let metadata = self.directory.metadata().map_err(|_| local_error())?;
        // SAFETY: geteuid has no preconditions.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(local_error());
        }
        Ok(())
    }

    fn name(key: &str) -> String {
        format!("state-{}.json", digest(key.as_bytes()))
    }

    fn lock_name(key: &str) -> String {
        format!("state-{}.lock", digest(key.as_bytes()))
    }

    fn read(&self, key: &str) -> Result<StoredState, Error> {
        self.validate()?;
        let name = Self::name(key);
        let file = match governor::open_child(&self.directory, &name, libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoredState {
                    version: 1,
                    ..StoredState::default()
                });
            }
            Err(_) => return Err(local_error()),
        };
        governor::validate_private_file(&file).map_err(|_| local_error())?;
        let mut bytes = Vec::new();
        file.take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| local_error())?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(local_error());
        }
        let state: StoredState = serde_json::from_slice(&bytes).map_err(|_| local_error())?;
        if state.version != 1
            || state.last_balance_kwh.is_some_and(|value| !value.is_finite())
            || state
                .threshold_kwh
                .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(local_error());
        }
        Ok(state)
    }

    fn write(&self, key: &str, state: &StoredState) -> Result<(), Error> {
        self.validate()?;
        let name = Self::name(key);
        match governor::open_child(&self.directory, &name, libc::O_RDONLY) {
            Ok(file) => governor::validate_private_file(&file).map_err(|_| local_error())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(local_error()),
        }
        let (temporary_name, mut temporary) =
            governor::create_temporary(&self.directory).map_err(|_| local_error())?;
        let result: Result<(), Error> = (|| {
            // SAFETY: the temporary descriptor was created exclusively here.
            if unsafe { libc::fchmod(temporary.as_raw_fd(), 0o600) } != 0 {
                return Err(local_error());
            }
            governor::validate_private_file(&temporary).map_err(|_| local_error())?;
            serde_json::to_writer(&mut temporary, state).map_err(|_| local_error())?;
            temporary.write_all(b"\n").map_err(|_| local_error())?;
            temporary.sync_all().map_err(|_| local_error())?;
            let target = CString::new(name).map_err(|_| local_error())?;
            // SAFETY: both names are single components in the pinned directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err(local_error());
            }
            self.directory.sync_all().map_err(|_| local_error())
        })();
        if result.is_err() {
            // SAFETY: the temporary was exclusively created by this call.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
        }
        result
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn now_unix_ms() -> Result<u64, Error> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| local_error())?
        .as_millis();
    u64::try_from(millis).map_err(|_| local_error())
}

fn observe_with(
    store: &Store,
    key: &str,
    balance_kwh: f64,
    threshold_kwh: Option<f64>,
    background: bool,
) -> Result<Value, Error> {
    // The per-key local lock serializes the read, the transition and the
    // write of one observation, so two processes cannot both report the same
    // crossing or both consume the polling window. It synchronizes this
    // private cache only; it is not the shared request governor.
    let _lock = KeyLock::acquire(&store.directory, key)?;
    let state = store.read(key)?;
    let now = now_unix_ms()?;
    if background
        && state
            .last_background_at_unix_ms
            .is_some_and(|last| now.saturating_sub(last) < MIN_POLL_SECONDS * 1000)
    {
        return Err(Error::new(
            "request_gap",
            "the background polling floor of 900 seconds has not elapsed",
        ));
    }
    let previous = match (state.threshold_kwh, threshold_kwh) {
        (Some(previous_limit), Some(limit)) if previous_limit == limit => state.last_balance_kwh,
        _ => None,
    };
    let alert = match threshold_kwh {
        Some(limit) => threshold_transition(
            previous,
            balance_kwh,
            limit,
            state.last_notified_at_unix_ms,
            now,
        )?,
        None => Value::Null,
    };
    let mut updated = state;
    updated.version = 1;
    updated.last_balance_kwh = Some(balance_kwh);
    updated.threshold_kwh = threshold_kwh;
    if alert["notified"] == json!(true) {
        updated.last_notified_at_unix_ms = Some(now);
    }
    if background {
        updated.last_background_at_unix_ms = Some(now);
    }
    store.write(key, &updated)?;
    Ok(json!({"alert": alert,
        "poll_floor_seconds": MIN_POLL_SECONDS,
        "cooldown_seconds": COOLDOWN_SECONDS,
        "source":"caller_supplied_value",
        "network_requests":0,
        "authorization":"none_a_caller_value_is_not_an_authorized_meter_reading",
        "scope":"per_key_local_state_not_the_shared_account_governor",
        "persisted_state":"caller_supplied_observation_threshold_timestamps_and_key_digest_in_the_private_state_directory"}))
}

/// Record one observation for an opaque caller key and return the resulting
/// transition. The key is never stored in clear text; only its digest names
/// the private state file and its lock file. A background observation inside
/// the polling floor is refused before any state change.
///
/// The balance is supplied by the caller. This function performs no network
/// request and neither collects nor authenticates any real meter, but it
/// does write local state: the caller-supplied observation, its threshold,
/// the observation timestamps and the digest of the caller key, all inside
/// the private state directory. It is not a substitute for the shared request
/// governor, and its per-key window is a local cache for one caller key only.
pub fn observe_threshold(
    key: &str,
    balance_kwh: f64,
    threshold_kwh: Option<f64>,
    background: bool,
) -> Result<Value, Error> {
    if key.is_empty() || key.chars().count() > MAX_FIELD {
        return Err(invalid("observation key must contain 1 to 256 characters"));
    }
    if !balance_kwh.is_finite() {
        return Err(invalid("observed balance must be finite"));
    }
    let store = Store::open()?;
    observe_with(&store, key, balance_kwh, threshold_kwh, background)
}

/// JSON input/output contract for CLI integration.
pub fn schema() -> Value {
    let text = json!({"type":"string","minLength":1,"maxLength":MAX_FIELD});
    let selector = json!({"oneOf":[
        {"type":"object","additionalProperties":false,"required":["identity_no"],"properties":{"identity_no":text.clone()}},
        {"type":"object","additionalProperties":false,"required":["campus","building","floor","room"],
            "properties":{"campus":text.clone(),"building":text.clone(),"floor":text.clone(),"room":text}}
    ]});
    json!({"input":{"type":"object","additionalProperties":false,
        "required":["operation","selector","authorization_confirmed"],
        "properties":{"operation":{"enum":["resolve","balance"]},"selector":selector,
            "authorization_confirmed":{"const":true,"description":"Caller assertion only; it does not establish upstream permission."},
            "threshold_kwh":{"type":["number","null"],"minimum":0,"description":"Absent and null are equivalent; no threshold means no alert state."},
            "poll_interval_seconds":{"type":["integer","null"],"minimum":MIN_POLL_SECONDS,"maximum":MAX_INTERVAL,"description":"Absent and null are equivalent; a value below 900 seconds is refused locally."}}},
        "output":{"type":"object","additionalProperties":false,
            "required":["schema_version","type","operation","result","reason","message","online_requested","network_requests","https_probe","authorization","unimplemented","poll_floor_seconds","background_floor_seconds","cooldown_seconds","persisted_state","next_step"],
            "properties":{"schema_version":{"const":1},"type":{"const":"electricity"},
                "operation":{"enum":["resolve","balance"]},"result":{"const":"blocked"},
                "reason":{"const":"directory_authorization_and_raw_evidence_disclosure_conflict"},
                "message":{"const":POLICY_MESSAGE},"online_requested":{"type":"boolean"},"network_requests":{"const":0},
                "https_probe":{"const":"not_performed_due_to_directory_privacy_blocker"},
                "authorization":{"const":"caller_selector_is_not_identity_or_permission_proof"},
                "unimplemented":{"type":"array","items":{"type":"string"}},
                "poll_floor_seconds":{"const":MIN_POLL_SECONDS},"background_floor_seconds":{"const":MIN_POLL_SECONDS},
                "cooldown_seconds":{"const":COOLDOWN_SECONDS},
                "persisted_state":{"const":"none_the_blocked_branch_writes_no_state"},"next_step":{"type":"string"}}},
        "library_output":{
            "parse_directory_fixture":{"type":["object","null"],"description":"The single matching sanitized fixture entry, or null when the selector matches no entry. Card numbers are never projected."},
            "parse_balance_fixture":{"type":"object","additionalProperties":false,
                "required":["result","balance","raw_evidence"],
                "properties":{"result":{"enum":["parsed","degraded"]},
                    "balance":{"type":["object","null"],"description":"The structured reading; null exactly when the result is degraded."},
                    "raw_evidence":{"oneOf":[{"type":"null"},
                        {"type":"object","additionalProperties":false,
                            "required":["encoding","data","content_type","byte_length","sha256","fallback_reason","raw_withheld","raw_withheld_reason","content_type_parameters_withheld"],
                            "allOf":[{"if":{"properties":{"raw_withheld":{"const":true}}},
                                "then":{"properties":{"data":{"type":"null"},"raw_withheld_reason":{"type":"string"}}},
                                "else":{"properties":{"data":{"type":"string"},"raw_withheld_reason":{"type":"null"}}}}],
                            "properties":{"encoding":{"const":"base64"},
                                "data":{"type":["string","null"],"contentEncoding":"base64"},
                                "content_type":{"type":["string","null"],"description":"Actual safe Content-Type, null when absent or withheld as unsafe. Never fabricated."},
                                "raw_withheld":{"type":"boolean"},
                                "raw_withheld_reason":{"type":["string","null"]},
                                "content_type_parameters_withheld":{"type":"boolean"},
                                "byte_length":{"type":"integer","minimum":0},
                                "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                                "fallback_reason":{"enum":FALLBACK_REASONS}}}]}}},
            "observe_threshold":{"type":"object","additionalProperties":false,
                "required":["alert","poll_floor_seconds","cooldown_seconds","source","network_requests","authorization","scope","persisted_state"],
                "properties":{"alert":{"type":["object","null"],"description":"The edge-triggered transition, or null when no threshold is configured."},
                    "poll_floor_seconds":{"const":MIN_POLL_SECONDS},
                    "cooldown_seconds":{"const":COOLDOWN_SECONDS},
                    "source":{"const":"caller_supplied_value","description":"The recorded balance comes from the caller. No meter is read."},
                    "network_requests":{"const":0},
                    "authorization":{"const":"none_a_caller_value_is_not_an_authorized_meter_reading"},
                    "scope":{"const":"per_key_local_state_not_the_shared_account_governor"},
                    "persisted_state":{"const":"caller_supplied_observation_threshold_timestamps_and_key_digest_in_the_private_state_directory","description":"The observation persists the caller-supplied value, threshold, timestamps and key digest in the private state directory. No meter is read and no network request is made."}}}},
        "library":{"parse_directory_fixture":"Sanitized synthetic directory selection; establishes no authorization.",
            "parse_balance_fixture":"Supplied balance parsing: reviewed-safe degradation retains exact originals; credentials, challenges, unsafe metadata and unreviewable bodies withhold reversible bytes and parsed values.",
            "parse_balance_page":"Structured balance reading: exactly two numeric leaf-tspan readings (no ancestor double counting), room, address, recharge rows and literal-only chart history. Computed object keys and object spread refuse uniqueness.",
            "restore_raw_evidence":"Re-read the exact bytes of a degraded evidence envelope offline; the declared length and digest must match.",
            "threshold_transition":"Pure edge-triggered transition with a one-hour cooldown.",
            "observe_threshold":"Persist the caller-supplied observation, its threshold, the observation timestamps and the digest of the caller key in the private directory (0700/0600) under a per-key local lock, and return the transition. Zero network requests: no meter is read or authenticated, and the per-key window is not the shared account governor."},
        "description":"The unauthenticated upstream directory exposes other people's card and meter data, so no remote request is made and no raw directory body is published. A caller selector is an assertion, not proof of permission. Optional threshold and interval fields treat absent and null as equivalent; intervals below 900 seconds are refused locally and background observations respect the same floor. Chart history is read only from an active classic inline script, from object members literally named data, never from JavaScript strings or comments. Observations consume caller-supplied values only: no network request and no meter is read or authenticated, while the private state keeps the caller-supplied observation, its threshold, the observation timestamps and the digest of the caller key; the per-key local lock that serializes concurrent processes is a cache synchronization device, not the shared account governor. The blocked branch performs no request and persists nothing. Synthetic fixtures are not online service acceptance."})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    const PAGE: &str = "<svg><tspan>25.5</tspan><tspan>1.2</tspan></svg><div style='float: left'><p class='shadow'>知行楼</p><p class='shadow'>地址:北京市</p></div><table><tbody><tr><td>2024-05-01</td><td>100</td></tr></tbody></table><script>x={data:[\"2024-05-01\"],series:{data:[1.2]}};</script>";

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "buaa-electricity-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self { root }
        }

        fn store(&self) -> Store {
            Store::open_at(&self.root.join("state")).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn directory_selects_only_the_requested_meter() {
        let source = br#"[{"id":1,"identityNo":"card1","name":"mine","campus":"A","building":"B","floor":"1","room":"101"},{"id":2,"identityNo":"card2","name":"other"}]"#;
        for selector in [
            r#"{"identity_no":"card1"}"#,
            r#"{"campus":"A","building":"B","floor":"1","room":"101"}"#,
        ] {
            let selected = parse_directory_fixture(source, selector).unwrap().unwrap();
            assert_eq!(selected["id"], "1");
            assert!(!selected.to_string().contains("card2"));
            assert!(!selected.to_string().contains("identityNo"));
        }
    }

    #[test]
    fn directory_uses_literal_scalar_types_and_ignores_metadata_objects() {
        let selector = r#"{"identity_no":"a"}"#;
        let object_id = br#"[{"id":{"$serde_json::private::RawValue":"1"},"identityNo":"a"}]"#;
        assert!(parse_directory_fixture(object_id, selector).is_err());

        let source = br#"[{"id":9007199254740993,"identityNo":"a","name":"$serde_json::private::RawValue","address":{"$serde_json::private::RawValue":"x"},"metadata":{"$serde_json::private::RawValue":"0"}}]"#;
        let selected = parse_directory_fixture(source, selector).unwrap().unwrap();
        assert_eq!(selected["id"], "9007199254740993");
        assert_eq!(selected["name"], "$serde_json::private::RawValue");
        assert!(selected["address"].is_null());

        let source = br#"[{"id":"$serde_json::private::RawValue","identityNo":7,"floor":-2}]"#;
        let selected = parse_directory_fixture(source, r#"{"identity_no":"7"}"#).unwrap().unwrap();
        assert_eq!(selected["id"], "$serde_json::private::RawValue");
        assert_eq!(selected["floor"], "-2");
    }

    #[test]
    fn utf8_balance_readings_and_history() {
        let page = parse_balance_page(PAGE.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
        assert_eq!(page["remaining_kwh"], 25.5);
        assert_eq!(page["yesterday_usage_kwh"], 1.2);
        assert_eq!(page["room"], "知行楼");
        assert_eq!(page["address"], "北京市");
        assert_eq!(page["recharge_records"][0]["cells"][1], "100");
        assert_eq!(page["history"]["usage_kwh"][0], 1.2);
        assert_eq!(page["charset"], "utf-8");
    }

    #[test]
    fn gbk_balance_readings_and_history() {
        let bytes = b"<svg><tspan>25.5</tspan><tspan>1.2</tspan></svg><div style='float:left'><p class='shadow'>\xd6\xaa\xd0\xd0\xc2\xa5</p><p class='shadow'>\xb5\xd8\xd6\xb7:\xb1\xb1\xbe\xa9\xca\xd0</p></div><table><tbody><tr><td>100</td></tr></tbody></table><script>x={data:[\"a\"],data:[1]}</script>";
        let page = parse_balance_page(bytes, Some("text/html; charset=GBK")).unwrap();
        assert_eq!(page["room"], "知行楼");
        assert_eq!(page["address"], "北京市");
        assert_eq!(page["remaining_kwh"], 25.5);
        assert_eq!(page["charset"], "gbk");
    }

    #[test]
    fn history_ignores_strings_and_comments() {
        let chart = script_history("option={xAxis:{data:[\"a,b\",\"c\"]},series:{data:[1.0,2.5]}}")
            .unwrap()
            .unwrap();
        assert_eq!(chart.0, json!(["a,b","c"]));
        assert_eq!(chart.1, json!([1.0, 2.5]));
        // A string or a comment that mentions data cannot supply the arrays.
        for script in [
            "const note = 'data:[\"fake\"],data:[999]';x={data:[\"a\"],data:[1]}",
            "/*data:[\"fake\"],data:[999]*/x={data:[\"a\"],data:[1]}",
        ] {
            let chart = script_history(script).unwrap().unwrap();
            assert_eq!(chart.0, json!(["a"]));
            assert_eq!(chart.1, json!([1]));
        }
    }

    #[test]
    fn history_requires_literal_types_and_preserves_numbers() {
        let chart = script_history(r#"x={data:["$serde_json::private::RawValue"],series:{data:[9007199254740993,-2,1.25,1e2]}}"#)
            .unwrap().unwrap();
        assert_eq!(chart.0, json!(["$serde_json::private::RawValue"]));
        assert_eq!(chart.1[0].as_u64(), Some(9007199254740993));
        assert_eq!(chart.1[1], json!(-2));
        assert_eq!(chart.1[2], json!(1.25));
        assert_eq!(chart.1[3], json!(100.0));

        for script in [
            r#"x={data:[{"$serde_json::private::RawValue":"a"}],series:{data:[1]}}"#,
            r#"x={data:["a"],series:{data:[{"$serde_json::private::RawValue":"0"}]}}"#,
            r#"x={data:["a"],series:{data:["1"]}}"#,
            r#"x={data:["a","b"],series:{data:[1]}}"#,
        ] {
            assert_eq!(script_history(script), Err("history_ambiguous"));
        }

        let page = PAGE.replace("data:[1.2]", r#"data:[{"$serde_json::private::RawValue":"0"}]"#);
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["raw_evidence"]["fallback_reason"], "history_ambiguous");
        let (original, _) = restore_raw_evidence(&output["raw_evidence"]).unwrap();
        assert_eq!(original, page.as_bytes());
    }

    #[test]
    fn comment_trivia_and_escaped_keys_cannot_hide_competing_history() {
        let page = format!("{PAGE}<script>/*note*/--> y={{data:[\"fake\"],series:{{data:[9]}}}};\n</script>");
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
            .unwrap();
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["balance"]["history"]["dates"], json!(["2024-05-01"]));
        let page = format!("{PAGE}<script>y={{d\\u0061ta:[\"other\"],series:{{d\\u0061ta:[9]}}}};</script>");
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
            .unwrap();
        assert_eq!(output["result"], "degraded");
        assert!(output["balance"].is_null());
    }

    #[test]
    fn legacy_meta_charset_precedes_utf8_guess_and_conflicts_withhold() {
        let ascii = PAGE.replace("知行楼", "ROOM").replace("北京市", "ADDR");
        let (before, after) = ascii.split_once("ROOM").unwrap();
        let mut bytes = b"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=GBK\">".to_vec();
        bytes.extend_from_slice(before.as_bytes());
        // C2 A9 is valid UTF-8 as ©, but the explicit GBK source means 漏.
        bytes.extend_from_slice(b"\xc2\xa9");
        bytes.extend_from_slice(after.as_bytes());
        let output = parse_balance_fixture(&bytes, Some("text/html")).unwrap();
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["balance"]["room"], "漏");
        assert_eq!(output["balance"]["charset"], "gbk");
        for declaration in [
            "<meta charset=utf-8><meta http-equiv=Content-Type content='text/html; charset=GBK'>",
            "<meta http-equiv=Content-Type content='text/html; charset=unknown'>",
        ] {
            let page = format!("{declaration}{PAGE}");
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html")).unwrap();
            assert_eq!(output["result"], "degraded");
            assert_eq!(output["raw_evidence"]["raw_withheld"], true);
        }
    }

    #[test]
    fn charsetless_meta_uses_header_or_normal_encoding_selection() {
        let meta = "<meta http-equiv=\"Content-Type\" content=\"text/html\">";
        let page = format!("{meta}{PAGE}");
        assert_eq!(declared_charset(None, page.as_bytes()), Ok(None));
        for content_type in [None, Some("text/html"), Some("text/html; charset=utf-8")] {
            let output = parse_balance_fixture(page.as_bytes(), content_type).unwrap();
            assert_eq!(output["result"], "parsed", "{content_type:?}");
            assert_eq!(output["balance"]["room"], "知行楼");
            assert_eq!(output["balance"]["charset"], "utf-8");
        }

        let ascii = PAGE.replace("知行楼", "ROOM").replace("北京市", "ADDR");
        let (before, after) = ascii.split_once("ROOM").unwrap();
        let mut bytes = format!("{meta}<div style='width:100%'></div>{before}").into_bytes();
        // C2 A9 is valid UTF-8, but an explicit GBK header selects 漏.
        bytes.extend_from_slice(b"\xc2\xa9");
        bytes.extend_from_slice(after.as_bytes());
        let output = parse_balance_fixture(&bytes, Some("text/html; charset=GBK")).unwrap();
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["balance"]["room"], "漏");
        assert_eq!(output["balance"]["charset"], "gbk");

        let quoted = format!("<meta http-equiv=Content-Type content='text/html; note=\"x; charset=gbk\"; charset=utf-8'>{PAGE}");
        assert_eq!(declared_charset(None, quoted.as_bytes()), Ok(Some("utf-8")));
        assert_eq!(parse_balance_fixture(quoted.as_bytes(), Some("text/html")).unwrap()["result"], "parsed");
        let single_quoted = format!("<meta http-equiv=Content-Type content=\"text/html; charset='utf-8'\">{PAGE}");
        assert_eq!(parse_balance_fixture(single_quoted.as_bytes(), Some("text/html")).unwrap()["result"], "parsed");
        assert_eq!(parse_balance_fixture(PAGE.as_bytes(), Some("text/html; charset=\"utf-8\"")).unwrap()["result"], "parsed");
    }

    #[test]
    fn malformed_or_conflicting_charset_metadata_is_withheld() {
        for declaration in [
            "<meta http-equiv=Content-Type content='text/html; charset'>",
            "<meta http-equiv=Content-Type content='text/html; charset='>",
            "<meta http-equiv=Content-Type content='text/html; charset=\"utf-8'>",
            "<meta charset='\"utf-8\"'>",
            "<meta http-equiv=Content-Type content='text/html; charset=utf-8; charset=gbk'>",
            "<meta http-equiv=Content-Type content='text/html; charset=unknown'>",
            "<meta http-equiv=Content-Type content='application/json'>",
        ] {
            let page = format!("{declaration}{PAGE}");
            assert_eq!(declared_charset(Some("text/html"), page.as_bytes()), Err("unsupported_charset"));
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html")).unwrap();
            assert_eq!(output["result"], "degraded", "{declaration}");
            assert_eq!(output["raw_evidence"]["raw_withheld"], true);
            assert!(output["raw_evidence"]["data"].is_null());
        }
        for content_type in [
            "text/html; charset",
            "text/html; charset=",
            "text/html; charset=\"utf-8",
            "text/html; charset='utf-8'",
            "text/html; charset=\"utf-8\"junk",
            "text/html; charset=utf-8; charset=gbk",
            "text/html; charset=unknown",
            "text/html; charset=utf-8; proof=opaque-fixture-value",
        ] {
            let output = parse_balance_fixture(PAGE.as_bytes(), Some(content_type)).unwrap();
            assert_eq!(output["result"], "degraded", "{content_type}");
            assert!(output["raw_evidence"]["content_type"].is_null());
            assert_eq!(output["raw_evidence"]["raw_withheld"], true);
            assert!(output["raw_evidence"]["data"].is_null());
            assert!(!output.to_string().contains("opaque-fixture-value"));
        }
    }

    #[test]
    fn percentages_do_not_block_balance_or_exact_safe_fallback() {
        let page = format!("<div style='width:100%;height:100%'><output>50%</output></div>{PAGE}")
            .replace("series:{data:[1.2]}", "series:{data:[1.2]},grid:{width:\"100%\",height:\"100%\"}");
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["balance"]["remaining_kwh"], 25.5);
        assert_eq!(output["balance"]["history"]["usage_kwh"], json!([1.2]));
        assert!(output["raw_evidence"].is_null());

        for (bytes, content_type) in [
            (b"<p style='width:100%'><output>50% complete; %41%42</output></p>".as_slice(), "text/html; charset=utf-8"),
            (b"<p style='width:100%'>\xd6\xaa\xd0\xd0\xc2\xa5</p>".as_slice(), "text/html; charset=gbk"),
            (br#"{"load":"100%","label":"%41%42"}"#.as_slice(), "application/json"),
        ] {
            let output = parse_balance_fixture(bytes, Some(content_type)).unwrap();
            assert_eq!(output["result"], "degraded", "{content_type}");
            assert_eq!(output["raw_evidence"]["raw_withheld"], false);
            assert_eq!(output["raw_evidence"]["byte_length"], bytes.len());
            assert_eq!(output["raw_evidence"]["sha256"], digest(bytes));
            let (restored, restored_type) = restore_raw_evidence(&output["raw_evidence"]).unwrap();
            assert_eq!(restored.as_slice(), bytes);
            assert_eq!(restored_type.as_deref(), Some(content_type));
        }
    }

    #[test]
    fn source_controls_with_unknown_names_are_never_disclosed() {
        for control in [
            "<form><input name='user_name' value='opaque-fixture-value'></form>",
            "<form><input name='account_ref' value='opaque-fixture-value'></form>",
            "<input form='absent' name='account_ref' value='opaque-fixture-value'>",
            "<form><input disabled name='account_ref' value='opaque-fixture-value'></form>",
            "<form><input type='hidden' name='account_ref' value='opaque-fixture-value'></form>",
            "<template><form><input name='account_ref' value='opaque-fixture-value'></form></template>",
            "<noscript><form><input name='account_ref' value='opaque-fixture-value'></form></noscript>",
            "<form><textarea name='account_ref'>opaque-fixture-value</textarea></form>",
            "<form><select name='account_ref'><option>opaque-fixture-value</option></select></form>",
            "<form><button name='account_ref' value='opaque-fixture-value'>Go</button></form>",
        ] {
            let page = format!("{PAGE}{control}");
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
            assert_eq!(output["result"], "degraded", "{control}");
            assert!(output["balance"].is_null(), "{control}");
            assert_eq!(output["raw_evidence"]["raw_withheld"], true, "{control}");
            assert!(output["raw_evidence"]["data"].is_null(), "{control}");
            assert!(!output.to_string().contains("opaque-fixture-value"), "{control}");
            assert!(restore_raw_evidence(&output["raw_evidence"]).is_err());
            assert_eq!(parse_balance_page(page.as_bytes(), Some("text/html; charset=utf-8")), Err("response_withheld"));
        }
    }

    #[test]
    fn percent_encoded_private_names_and_duplicate_json_members_are_withheld() {
        for body in [
            r#"{"to%6ben":"opaque-fixture-value"}"#,
            r#"{"to%6ben":"opaque-fixture-value","to%6ben":"ordinary"}"#,
            r#"{"p%61ssword":"opaque-fixture-value"}"#,
            r#"{"%2570assword":"opaque-fixture-value"}"#,
            r#"{"%E5%AF%86%E7%A0%81":"opaque-fixture-value"}"#,
            r#"{"%C3%DC%C2%EB":"opaque-fixture-value"}"#,
            r#"{"公告%C3%DC%C2%EB":"opaque-fixture-value"}"#,
            "to%6ben=opaque-fixture-value",
            "<input name='p%61ssword' value='opaque-fixture-value'>",
        ] {
            let output = parse_balance_fixture(body.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
            assert_eq!(output["result"], "degraded", "{body}");
            assert_eq!(output["raw_evidence"]["raw_withheld"], true, "{body}");
            assert_eq!(output["raw_evidence"]["raw_withheld_reason"], "sensitive_response_material");
            assert!(output["raw_evidence"]["data"].is_null());
            assert!(!output.to_string().contains("opaque-fixture-value"));
        }
        let mut deeply_encoded = "%70assword".to_owned();
        for _ in 0..8 { deeply_encoded = deeply_encoded.replacen('%', "%25", 1); }
        let body = format!(r#"{{"{deeply_encoded}":"opaque-fixture-value"}}"#);
        let output = parse_balance_fixture(body.as_bytes(), Some("application/json")).unwrap();
        assert_eq!(output["raw_evidence"]["raw_withheld"], true);
        assert_eq!(output["raw_evidence"]["raw_withheld_reason"], "response_safety_unreviewed");
        assert!(output["raw_evidence"]["data"].is_null());
    }

    #[test]
    fn supplied_private_bodies_and_metadata_never_escape_in_evidence() {
        for bytes in [
            br#"{"password":"private-value"}"#.as_slice(),
            br#"{"pass\u0077ord":"private-value"}"#.as_slice(),
            br#"{"pass\u0077ord":"private-value","password":"overwritten"}"#.as_slice(),
            br#"{"captcha":"private-value"}"#.as_slice(),
            br#"{"to%6ben":"private-value"}"#.as_slice(),
            br#"<input name='pass&#119;ord' value='private-value'>"#.as_slice(),
            br#"<input name='token' value='private-value'>"#.as_slice(),
            br#"<form><input type='password' value='private-value'></form>"#.as_slice(),
            br#"<img alt='captcha' src='/private-value'>"#.as_slice(),
            b"\xff\xfe\x00".as_slice(),
        ] {
            let output = parse_balance_fixture(bytes, Some("text/html; charset=utf-8")).unwrap();
            assert_eq!(output["result"], "degraded");
            assert!(output["balance"].is_null());
            assert!(output["raw_evidence"]["data"].is_null());
            assert_eq!(output["raw_evidence"]["raw_withheld"], true);
            assert!(!output.to_string().contains("private-value"));
            assert!(restore_raw_evidence(&output["raw_evidence"]).is_err());
        }
        let page = PAGE.replace("知行楼", "password=private-value");
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
        assert!(output["balance"].is_null());
        assert!(parse_balance_page(page.as_bytes(), Some("text/html; charset=utf-8")).is_err());
        let output = parse_balance_fixture(PAGE.as_bytes(), Some("text/html; token=private-value")).unwrap();
        assert!(output["raw_evidence"]["content_type"].is_null());
        assert!(output["raw_evidence"]["data"].is_null());
        assert!(!output.to_string().contains("private-value"));
        for safe in ["{\"公告\":\"正常中文\"}", r#"{"title":"\u4e2d\u6587"}"#] {
            let output = parse_balance_fixture(safe.as_bytes(), Some("application/json")).unwrap();
            let (restored, _) = restore_raw_evidence(&output["raw_evidence"]).unwrap();
            assert_eq!(restored.as_slice(), safe.as_bytes());
        }
    }

    #[test]
    fn ambiguous_history_is_refused() {
        for script in [
            "x={data:[\"a\"],data:[1],data:[2]}",
            "x={series:{data:[\"a\"]},other:{data:[\"b\"],data:[1]}}",
            "x={data:[\"a\"],data:[1]",
            "x={data:[1],data:[\"a\"]}",
        ] {
            assert!(script_history(script).is_err(), "{script}");
        }
    }

    #[test]
    fn chart_literal_boundaries_and_competing_scripts() {
        let pair = script_history("x={'data':[\"a\"],series:{'data':[1]}};")
            .unwrap().unwrap();
        assert_eq!(pair.0, json!(["a"]));
        assert_eq!(pair.1, json!([1]));
        assert!(script_history("{data:[\"fake-date\"]}{data:[999]}").is_err());
        assert!(script_history("<!-- {data:[\"fake\"],data:[9]}\n-->")
            .unwrap().is_none());
        for script in [
            "function f(){return /({data:[\"fake\"],data:[9]})/;}",
            "x={data:[\"Mon\"].concat([\"Tue\"]),series:{data:[1].concat([2])}};",
        ] {
            assert!(script_history(script).is_err(), "{script}");
        }
        let page = format!("{PAGE}<script>y={{data:[\"other\"],series:{{data:[9]}}}};const note=`x`;</script>");
        let result = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
            .unwrap();
        assert_eq!(result["result"], "degraded");
        assert_eq!(result["raw_evidence"]["fallback_reason"], "script_unlexable");
        assert!(schema()["library_output"]["observe_threshold"].is_object());
        assert!(schema().get("observe_threshold").is_none());
    }

    #[test]
    fn extra_reading_candidate_degrades_but_inactive_scripts_do_not() {
        // A third numeric tspan reading leaves the intended pair ambiguous.
        let output = parse_balance_fixture(
            format!("<svg><tspan>999</tspan></svg>{PAGE}").as_bytes(),
            Some("text/html; charset=utf-8"),
        )
        .unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(
            output["raw_evidence"]["fallback_reason"],
            "balance_values_ambiguous"
        );
        // Inactive or external script bodies cannot change a valid history.
        for injection in [
            "<script type=\"text/plain\">x={data:[\"fake\"],data:[9]};</script>",
            "<script src=\"/chart.js\"></script>",
            "<template><script>x={data:[\"fake\"],data:[9]};</script></template>",
            "<svg><script href=\"/chart.js\">x={data:[\"fake\"],series:{data:[9]}};</script></svg>",
            "<svg xmlns:xlink=\"http://www.w3.org/1999/xlink\"><script xlink:href=\"/chart.js\">x={data:[\"fake\"],series:{data:[9]}};</script></svg>",
        ] {
            let output = parse_balance_fixture(
                format!("{injection}{PAGE}").as_bytes(),
                Some("text/html; charset=utf-8"),
            )
            .unwrap();
            assert_eq!(output["result"], "parsed", "{injection}");
            assert_eq!(output["balance"]["history"]["usage_kwh"][0], 1.2, "{injection}");
        }
    }

    #[test]
    fn dynamic_members_cannot_supply_or_override_unique_history() {
        for script in [
            r#"y={["data"]:["other"],series:{data:[9]}};"#,
            r#"y=({["data"]:["other"],series:{data:[9]}});"#,
            r#"y={["d\u0061ta"]:["other"],series:{data:[9]}};"#,
            r#"y={...other,data:["other"],series:{data:[9]}};"#,
            r#"y={data:["other"],series:{data:[9]},...other};"#,
        ] {
            assert!(script_history(script).is_err(), "{script}");
            let page = format!("{PAGE}<script>{script}</script>");
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
            assert_eq!(output["result"], "degraded", "{script}");
            assert!(output["balance"].is_null());
            if !script.contains("\\u") {
                assert_eq!(output["raw_evidence"]["fallback_reason"], "script_unlexable");
                let (original, _) = restore_raw_evidence(&output["raw_evidence"]).unwrap();
                assert_eq!(original.as_slice(), page.as_bytes());
            }
        }
        // Ordinary arrays, including an array expression in a statement
        // block, are not computed object keys and do not compete with PAGE.
        let page = format!("{PAGE}<script>const values=[1,2];{{[3,4];}}</script>");
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
            .unwrap();
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["balance"]["history"]["usage_kwh"], json!([1.2]));
    }

    #[test]
    fn nested_tspan_text_has_only_one_reading_owner() {
        let original = "<svg><tspan>25.5</tspan><tspan>1.2</tspan></svg>";
        let single = PAGE.replacen(original,
            "<svg><text><tspan><tspan>25.5</tspan></tspan></text></svg>", 1);
        let output = parse_balance_fixture(single.as_bytes(), Some("text/html; charset=utf-8"))
            .unwrap();
        assert_eq!(output["result"], "degraded");
        assert!(output["balance"].is_null());
        assert_eq!(output["raw_evidence"]["fallback_reason"], "balance_values_ambiguous");
        let (retained, _) = restore_raw_evidence(&output["raw_evidence"]).unwrap();
        assert_eq!(retained.as_slice(), single.as_bytes());
        let siblings = PAGE.replacen(original,
            "<svg><text><tspan><tspan>25.5</tspan><tspan>1.2</tspan></tspan></text></svg>", 1);
        for page in [PAGE, siblings.as_str()] {
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
            assert_eq!(output["result"], "parsed");
            assert_eq!(output["balance"]["remaining_kwh"], 25.5);
            assert_eq!(output["balance"]["yesterday_usage_kwh"], 1.2);
        }
    }

    #[test]
    fn unicode_comment_ends_and_unsupported_objects_preserve_ambiguity() {
        for separator in ['\u{2028}', '\u{2029}'] {
            let suffix = format!("//comment{separator}y={{data:[\"other\"],series:{{data:[9]}}}};</script>");
            let page = PAGE.replace("</script>", &suffix);
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
            assert_eq!(output["result"], "degraded");
            assert_eq!(output["raw_evidence"]["fallback_reason"], "history_ambiguous");
            assert_eq!(output["raw_evidence"]["data"], STANDARD.encode(page.as_bytes()));
        }
        let page = format!("{PAGE}<script>y=({{data:[\"other\"],series:{{data:[9]}}}});</script>");
        let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
            .unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["raw_evidence"]["fallback_reason"], "script_unlexable");

        let without_chart = PAGE.split("<script>").next().unwrap();
        for reference in ["href", "xlink:href"] {
            let page = format!("{without_chart}<svg xmlns:xlink=\"http://www.w3.org/1999/xlink\"><script {reference}=\"/chart.js\">x={{data:[\"fake\"],series:{{data:[9]}}}};</script></svg>");
            let output = parse_balance_fixture(page.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
            assert_eq!(output["result"], "degraded");
            assert_eq!(output["raw_evidence"]["fallback_reason"], "history_missing");
        }
    }

    #[test]
    fn threshold_edges_non_edges_and_cooldown() {
        let baseline = threshold_transition(None, 9.0, 10.0, None, 100).unwrap();
        assert!(baseline["transition"].is_null());
        let same_side = threshold_transition(Some(9.0), 8.0, 10.0, None, 100).unwrap();
        assert!(same_side["transition"].is_null());
        let below = threshold_transition(Some(11.0), 10.0, 10.0, None, 100).unwrap();
        assert_eq!(below["transition"], "below_threshold");
        assert_eq!(below["notified"], true);
        let suppressed = threshold_transition(Some(9.0), 11.0, 10.0, Some(100), 101).unwrap();
        assert_eq!(suppressed["transition"], "above_threshold");
        assert_eq!(suppressed["notified"], false);
        assert_eq!(suppressed["cooldown_suppressed"], true);
        let after = threshold_transition(
            Some(9.0),
            11.0,
            10.0,
            Some(100),
            100 + COOLDOWN_SECONDS * 1000,
        )
        .unwrap();
        assert_eq!(after["notified"], true);
    }

    #[test]
    fn observation_state_persists_and_respects_the_background_floor() {
        let fixture = Fixture::new();
        let store = fixture.store();
        let mut state = StoredState {
            version: 1,
            ..StoredState::default()
        };
        state.last_balance_kwh = Some(9.0);
        state.threshold_kwh = Some(10.0);
        store.write("meter", &state).unwrap();
        let reloaded = store.read("meter").unwrap();
        assert_eq!(reloaded.last_balance_kwh, Some(9.0));
        let edge =
            threshold_transition(reloaded.last_balance_kwh, 11.0, 10.0, None, 200).unwrap();
        assert_eq!(edge["transition"], "above_threshold");
        // A background observation inside the floor is refused.
        let mut background = StoredState {
            version: 1,
            ..StoredState::default()
        };
        background.last_background_at_unix_ms = Some(now_unix_ms().unwrap());
        store.write("background", &background).unwrap();
        let error = observe_with(&store, "background", 9.0, Some(10.0), true).unwrap_err();
        assert_eq!(error.code, "request_gap");
        // The same observation without the background flag is accepted.
        assert!(observe_with(&store, "background", 9.0, Some(10.0), false).is_ok());
    }

    const CHILD_ROOT: &str = "BUAA_ELECTRICITY_CHILD_ROOT";
    const CHILD_KEY: &str = "BUAA_ELECTRICITY_CHILD_KEY";
    const CHILD_BALANCE: &str = "BUAA_ELECTRICITY_CHILD_BALANCE";
    const CHILD_BACKGROUND: &str = "BUAA_ELECTRICITY_CHILD_BACKGROUND";
    const CHILD_GATE: &str = "BUAA_ELECTRICITY_CHILD_GATE";
    const CHILD_MARKER: &str = "ELECTRICITY_CHILD_RESULT";

    /// The child half of the concurrency regressions. It waits for the gate,
    /// records one observation in the shared private directory and reports the
    /// outcome on stdout. `None` means this process is not a child.
    fn child_observation() -> Option<()> {
        let root = std::env::var(CHILD_ROOT).ok()?;
        let key = std::env::var(CHILD_KEY).ok()?;
        let balance: f64 = std::env::var(CHILD_BALANCE).ok()?.parse().ok()?;
        let background = std::env::var(CHILD_BACKGROUND).ok()? == "1";
        let gate = std::env::var(CHILD_GATE).ok()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !std::path::Path::new(&gate).exists() {
            if std::time::Instant::now() >= deadline {
                println!("{CHILD_MARKER} notified=false error=gate_timeout");
                return Some(());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let store = match Store::open_at(std::path::Path::new(&root)) {
            Ok(store) => store,
            Err(error) => {
                println!("{CHILD_MARKER} notified=false error={}", error.code);
                return Some(());
            }
        };
        match observe_with(&store, &key, balance, Some(10.0), background) {
            Ok(value) => println!(
                "{CHILD_MARKER} notified={} error=none",
                value["alert"]["notified"]
            ),
            Err(error) => println!("{CHILD_MARKER} notified=false error={}", error.code),
        }
        Some(())
    }

    /// Run `count` independent processes against one private directory and
    /// collect the result line of every child.
    fn spawn_observations(
        root: &std::path::Path,
        test_name: &str,
        key: &str,
        balance: f64,
        background: bool,
        count: usize,
    ) -> Vec<String> {
        let exe = std::env::current_exe().expect("test binary path");
        let gate = root.join("gate");
        let mut children = Vec::new();
        for _ in 0..count {
            let mut command = std::process::Command::new(&exe);
            command
                .arg(test_name)
                .arg("--nocapture")
                .env(CHILD_ROOT, root.join("state"))
                .env(CHILD_KEY, key)
                .env(CHILD_BALANCE, balance.to_string())
                .env(CHILD_BACKGROUND, if background { "1" } else { "0" })
                .env(CHILD_GATE, &gate)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            children.push(command.spawn().expect("child test process"));
        }
        // Release every child at the same moment so the observation window
        // really overlaps between processes.
        std::fs::write(&gate, b"go").expect("gate file");
        let mut results = Vec::new();
        for child in children {
            let output = child.wait_with_output().expect("child output");
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some(result) = line.strip_prefix(CHILD_MARKER) {
                    results.push(result.trim().to_owned());
                }
            }
        }
        assert_eq!(results.len(), count, "every child must report one result");
        results
    }

    #[test]
    fn concurrent_crossing_notifies_once_across_processes() {
        if child_observation().is_some() {
            return;
        }
        let fixture = Fixture::new();
        let store = fixture.store();
        let mut state = StoredState {
            version: 1,
            ..StoredState::default()
        };
        state.last_balance_kwh = Some(9.0);
        state.threshold_kwh = Some(10.0);
        store.write("meter", &state).unwrap();

        let results = spawn_observations(
            &fixture.root,
            "concurrent_crossing_notifies_once_across_processes",
            "meter",
            11.0,
            false,
            4,
        );
        let notified = results
            .iter()
            .filter(|result| result.contains("notified=true"))
            .count();
        assert_eq!(notified, 1, "{results:?}");
        assert_eq!(
            results
                .iter()
                .filter(|result| result.contains("error=none"))
                .count(),
            4,
            "{results:?}"
        );
    }

    #[test]
    fn concurrent_background_observations_keep_the_polling_window() {
        if child_observation().is_some() {
            return;
    }
        let fixture = Fixture::new();
        let store = fixture.store();
        let mut state = StoredState {
            version: 1,
            ..StoredState::default()
        };
        state.last_balance_kwh = Some(9.0);
        state.threshold_kwh = Some(10.0);
        store.write("meter", &state).unwrap();

        let results = spawn_observations(
            &fixture.root,
            "concurrent_background_observations_keep_the_polling_window",
            "meter",
            9.0,
            true,
            4,
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.contains("error=none"))
                .count(),
            1,
            "{results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.contains("error=request_gap"))
                .count(),
            3,
            "{results:?}"
        );
    }

    #[test]
    fn rejects_interval_floor_and_unknown_fields() {
        let input = r#"{"operation":"balance","selector":{"identity_no":"synthetic"},"authorization_confirmed":true,"poll_interval_seconds":899}"#;
        assert_eq!(run(input, true).unwrap_err().code, "invalid_input");
        assert!(parse_input(
            &input
                .replace("899", "900")
                .replace("\"operation\"", "\"unexpected\":true,\"operation\"")
        )
        .is_err());
    }

    #[test]
    fn live_and_offline_block_without_probe_or_identifier_echo() {
        let input = r#"{"operation":"balance","selector":{"identity_no":"synthetic-private-selector"},"authorization_confirmed":true}"#;
        for online in [false, true] {
            let result = run(input, online).unwrap();
            assert_eq!(result["result"], "blocked");
            assert_eq!(result["message"], POLICY_MESSAGE);
            assert_eq!(result["network_requests"], 0);
            assert!(!result.to_string().contains("synthetic-private-selector"));
        }
    }

    #[test]
    fn degraded_fixture_preserves_original_bytes_and_absent_type() {
        let bytes = b"ordinary offline response";
        let output = parse_balance_fixture(bytes, None).unwrap();
        let raw = &output["raw_evidence"];
        assert_eq!(output["result"], "degraded");
        assert!(raw["content_type"].is_null());
        assert_eq!(
            STANDARD.decode(raw["data"].as_str().unwrap()).unwrap(),
            bytes.to_vec()
        );
        assert_eq!(raw["byte_length"], bytes.len());
        assert_eq!(raw["sha256"], digest(bytes));
        assert!(raw["fallback_reason"].is_string());
    }

    #[test]
    fn structural_failures_are_refused_with_precise_reasons() {
        // A page without a chart declaration has no verified history.
        let without_chart = PAGE.split("<script>").next().unwrap().to_owned();
        let output =
            parse_balance_fixture(without_chart.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["raw_evidence"]["fallback_reason"], "history_missing");

        // One chart array cannot be paired with a second one.
        let single_array = PAGE.replace("series:{data:[1.2]}", "");
        let output =
            parse_balance_fixture(single_array.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["raw_evidence"]["fallback_reason"], "history_ambiguous");

        // An address line without its documented prefix is not an address.
        let without_prefix = PAGE.replace("地址:北京市", "北京市");
        let output =
            parse_balance_fixture(without_prefix.as_bytes(), Some("text/html; charset=utf-8"))
                .unwrap();
        assert_eq!(output["result"], "degraded");
        assert_eq!(
            output["raw_evidence"]["fallback_reason"],
            "room_address_missing"
        );

        // A `data` array that is not an object member cannot declare history,
        // and it cannot displace the declaration of another script.
        let stray = format!("{PAGE}<script>var d = data:[1];</script>");
        let output =
            parse_balance_fixture(stray.as_bytes(), Some("text/html; charset=utf-8")).unwrap();
        assert_eq!(output["result"], "parsed");
        assert_eq!(output["balance"]["history"]["usage_kwh"][0], 1.2);
    }

    #[test]
    fn degraded_evidence_can_be_re_read_offline() {
        let bytes = b"<html><body>not a meter page</body></html>";
        let output = parse_balance_fixture(bytes, Some("text/html; charset=utf-8")).unwrap();
        assert_eq!(output["result"], "degraded");
        let (restored, content_type) = restore_raw_evidence(&output["raw_evidence"]).unwrap();
        assert_eq!(restored, bytes.to_vec());
        assert_eq!(content_type.as_deref(), Some("text/html; charset=utf-8"));
        // The restored bytes are the original response, not a re-rendering.
        let again = parse_balance_fixture(&restored, content_type.as_deref()).unwrap();
        assert_eq!(again["result"], "degraded");
        assert_eq!(
            again["raw_evidence"]["sha256"],
            output["raw_evidence"]["sha256"]
        );

        // A tampered envelope is refused instead of being re-parsed.
        let mut shortened = output["raw_evidence"].clone();
        shortened["byte_length"] = json!(1);
        assert!(restore_raw_evidence(&shortened).is_err());
        let mut edited = output["raw_evidence"].clone();
        let mut payload = STANDARD.decode(edited["data"].as_str().unwrap()).unwrap();
        payload.push(b'!');
        edited["data"] = json!(STANDARD.encode(&payload));
        assert!(restore_raw_evidence(&edited).is_err());
    }

    #[test]
    fn schema_matches_the_runtime_acceptance_set() {
        let schema = schema();
        assert_eq!(
            schema["input"]["properties"]["poll_interval_seconds"]["minimum"],
            MIN_POLL_SECONDS
        );
        assert_eq!(
            schema["input"]["properties"]["poll_interval_seconds"]["maximum"],
            MAX_INTERVAL
        );
        let reasons = schema["library_output"]["parse_balance_fixture"]["properties"]
            ["raw_evidence"]["oneOf"][1]["properties"]["fallback_reason"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(reasons.len(), FALLBACK_REASONS.len());
        for reason in FALLBACK_REASONS {
            assert!(reasons.contains(&json!(reason)), "{reason}");
        }

        // The runtime accepts exactly the integer set the schema publishes.
        for interval in ["900.5", "899", "-900", "2147483648"] {
            let input = format!(
                r#"{{"operation":"balance","selector":{{"identity_no":"synthetic"}},"authorization_confirmed":true,"poll_interval_seconds":{interval}}}"#
            );
            assert_eq!(
                run(&input, false).unwrap_err().code,
                "invalid_input",
                "{interval}"
            );
        }
        for interval in ["900", "900.0", "9e2", "2147483647.0"] {
            let input = format!(
                r#"{{"operation":"balance","selector":{{"identity_no":"synthetic"}},"authorization_confirmed":true,"poll_interval_seconds":{interval}}}"#
            );
            assert!(run(&input, false).is_ok(), "{interval}");
        }
    }

    #[test]
    fn directory_fixture_refuses_ambiguous_and_unknown_matches() {
        let duplicated = br#"[{"id":1,"identityNo":"card1"},{"id":2,"identityNo":"card1"}]"#;
        assert!(parse_directory_fixture(duplicated, r#"{"identity_no":"card1"}"#).is_err());
        let unique = br#"[{"id":1,"identityNo":"card1"}]"#;
        assert!(
            parse_directory_fixture(unique, r#"{"identity_no":"card2"}"#)
                .unwrap()
                .is_none()
        );
        // A selector that mixes both variants is not a member of either.
        let mixed = r#"{"operation":"balance","selector":{"identity_no":"a","campus":"b"},"authorization_confirmed":true}"#;
        assert!(run(mixed, false).is_err());
    }
}

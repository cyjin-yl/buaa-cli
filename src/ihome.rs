//! Governed, read-only adapter for the ihome appeal board (`i.buaa.edu.cn`).
//!
//! What this module implements, and what it deliberately does not:
//!
//! * It reads exactly two documented upstream endpoints over HTTPS only:
//!   `GET /api/appeal?limit=<int>&page=<int>` (listing) and
//!   `GET /api/appeal/<id>` (one appeal). Every request carries
//!   `Accept: application/json`, `Authorization: Bearer <token>` and
//!   `Referer: https://i.buaa.edu.cn/web/`.
//! * It never logs in. The SSO redirect-chain token (`?token=` / `#token=`) and
//!   the `appeal_pc_token` session cookie are produced by the session layer;
//!   this module only accepts an explicit bearer token plus an optional
//!   description of where that token came from. A missing token is refused as
//!   `authorization_required` before any cache or network access.
//!   Typed decoding wraps each token immediately in `Zeroizing`, including
//!   tokens decoded before a subsequent malformed or unknown field fails.
//!   Dispatch reads only the operation and ignores the other fields without
//!   constructing a generic JSON value or reserializing credentials. The
//!   caller's input buffer, serde parser scratch space, and reqwest/TLS-owned
//!   copies are outside this module's zeroization guarantee.
//! * Every remote request takes its own shared-governor lease and keeps it
//!   until the response body has been read and structured. A `429`/`Retry-After`
//!   or a `401`/`403`/challenge stops every further request. Nothing is
//!   retried automatically, and a rejected token is never refreshed here.
//! * A response that cannot be structured is returned as a degraded success
//!   that carries the original bytes (base64), the *observed* `content_type`
//!   (`null` when the upstream sent none, when its header value carries the
//!   submitted credential in any supported spelling, or when it is not a
//!   well-formed MIME type), the byte length, the SHA-256 of the body and a
//!   `fallback_reason`. Safety-latched or unreviewed challenge bodies and
//!   bodies carrying credential-marked JSON or HTML metadata are withheld
//!   from output; only their provenance is exposed.
//!   Those exact bytes are also stored in a
//!   private, credential-scoped cache so the degraded evidence can be re-read
//!   offline without another request.
//! * The supplied bearer token is never echoed. Every response body and
//!   decoded JSON string is inspected for the token and the reversible forms
//!   supported by `net::carries_secret` before projection or export. Matching
//!   is conservative: even an accidental substring match, especially with a
//!   short token, withholds the body rather than risking disclosure.
//!   A body that echoes the token is refused as `credential_echo`: no entry is
//!   projected, no raw bytes are exported and the body is not cached.
//!   Responses whose nested token inspection exceeds its bound are withheld as
//!   unreviewed, without claiming an echo or an authentication refusal.
//! * An explicit application-level authentication refusal (a root-level
//!   message that states the session is not authenticated) is not an empty
//!   listing. It is reported as `authentication_refused` and it settles the
//!   original lease as a credential rejection, so the shared governor latches
//!   and the next request requires an explicit resume. An ordinary business
//!   `success=false` answer stays an empty listing.
//! * A cached HTTP `401`/`403`, and a cached application-level refusal, are
//!   published to the shared governor on every cache read, so a replay of the
//!   same rejection cannot leave the governor unlatched.
//! * When a later page of a multi-page traversal cannot be fetched, the pages
//!   that were already admitted are preserved and reported as a `partial`
//!   traversal. The traversal is never reported as complete and the
//!   incremental cursor is not advanced.
//! * Attachments are never downloaded. The modern platform exposes no
//!   dedicated attachment endpoint; the legacy `php-ihome` upload/attachment
//!   routes are reference-only and their contract is UNKNOWN, so no attachment
//!   endpoint is guessed here. Only URLs that the upstream record itself
//!   declares are reported, with their presence, and they are never fetched.
//! * WebVPN URL encryption is an upstream client-side detail and is not
//!   implemented; only direct HTTPS to `i.buaa.edu.cn` is used. The upstream
//!   22:00-07:00 idle window is surfaced as an advisory hint only: it never
//!   blocks, delays, or rewrites a request.
//! * An ordinary upstream `success=false` answer is an empty listing, not a
//!   fault and not a retry trigger. An explicit authentication refusal inside
//!   that envelope is not an empty listing: it is reported as
//!   `authentication_refused` and it latches the shared governor.
//!
//! Nothing here has been exercised against the live campus service; the
//! endpoint contract is the documented one and the online acceptance of this
//! adapter is still unverified.

use crate::governor::{self, Governor, Outcome};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use crate::net::{self, CacheStatus, Error, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, FixedOffset, NaiveDateTime};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroizing;

const IHOME_ORIGIN: &str = "https://i.buaa.edu.cn";
const IHOME_API_PATH: &str = "/api/appeal";
const IHOME_DETAIL_PREFIX: &str = "/api/appeal/";
const IHOME_REFERER: &str = "https://i.buaa.edu.cn/web/";
const IHOME_HOST: &str = "i.buaa.edu.cn";
const CACHE_DIR: &str = ".buaa-cli-ihome-cache";

const MAX_INPUT: usize = 256 * 1024;
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 12 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_ENTRIES_PER_PAGE: usize = 2_000;
const MAX_REPLIES_PER_ENTRY: usize = 500;
const MAX_DEPARTMENTS_PER_ENTRY: usize = 100;
const MAX_ATTACHMENTS_PER_ENTRY: usize = 64;
const MAX_ATTACHMENT_URL_BYTES: usize = 2_048;
const MAX_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_REPLY_CONTENT_BYTES: usize = 64 * 1024;
const MAX_REPLY_PREVIEW_CHARS: usize = 512;
const MAX_KNOWN_ITEMS: usize = 2_000;
const MAX_LIMIT: u32 = 100;
const DEFAULT_LIMIT: u32 = 20;
const MAX_PAGES: u32 = 20;
const DEFAULT_PAGES: u32 = 1;
const MAX_PAGE: u32 = u32::MAX - MAX_PAGES;
const HEADER_NAMES: &[&str] = &[
    "content-type",
    "content-encoding",
    "content-length",
    "date",
    "etag",
    "last-modified",
    "retry-after",
];

/// Upstream fields that may carry declared attachment or image URLs.
const ATTACHMENT_FIELDS: &[&str] = &[
    "body_data",
    "image_1",
    "image_2",
    "image_3",
    "image_4",
    "image_1_link",
    "image_2_link",
    "image_3_link",
    "image_4_link",
];

fn invalid_input(message: &'static str) -> Error {
    Error::new("invalid_input", message)
}

fn invalid_url() -> Error {
    Error::new("invalid_url", "the ihome request URL is invalid")
}

fn cache_error() -> Error {
    Error::new("cache_error", "the ihome response cache is unavailable")
}

fn corrupt_cache() -> Error {
    Error::new("corrupt_cache", "the ihome response cache is invalid")
}

fn governor_error() -> Error {
    Error::new(
        "governor_denied",
        "the shared request governor cannot authorize or persist this request",
    )
}

fn network_error() -> Error {
    Error::new("network_error", "the ihome request failed")
}

fn body_limit() -> Error {
    Error::new("body_limit", "the ihome response exceeds its byte limit")
}

fn token_required() -> Error {
    Error::new(
        "authorization_required",
        "ihome requires an explicit bearer token from the session layer; this module never logs in",
    )
}

fn attachment_download_unsupported() -> Error {
    Error::new(
        "unsupported",
        "ihome attachment download is not implemented; the platform exposes no dedicated attachment endpoint and the legacy attachment contract is unknown",
    )
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}


// Construct literal JSON values ourselves: serde_json's Value visitor treats
// a reserved first member as RawValue when that feature is enabled. Inspect
// every member before last-member-wins insertion, including duplicates.
struct TokenInspection<'a> {
    token: &'a str,
    scan_decoded: bool,
    echo: bool,
    incomplete: bool,
}

impl TokenInspection<'_> {
    fn inspect(&mut self, text: &str, embedded_depth: usize, allow_embedded: bool) {
        if self.token.is_empty() { return; }
        if self.scan_decoded && !self.echo {
            self.echo = net::carries_secret(text.as_bytes(), self.token);
        }
        let trimmed = text.trim();
        if allow_embedded && trimmed.starts_with(['{', '[', '"']) {
            if embedded_depth >= 32 {
                self.incomplete = true;
                return;
            }
            // Optional embedded documents may instead be ordinary prose. Only
            // commit their echo fact after the whole embedded document parses.
            let prior = self.echo;
            let mut decoder = serde_json::Deserializer::from_str(trimmed);
            use serde::de::DeserializeSeed;
            let valid = LiteralSeed { inspection: self, embedded_depth: embedded_depth + 1, build: false }
                .deserialize(&mut decoder).is_ok() && decoder.end().is_ok();
            if !valid { self.echo = prior; }
        }
    }
}

struct LiteralSeed<'a, 't> {
    inspection: &'a mut TokenInspection<'t>,
    embedded_depth: usize,
    build: bool,
}

impl<'de> serde::de::DeserializeSeed<'de> for LiteralSeed<'_, '_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for LiteralSeed<'_, '_> {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("a literal JSON value") }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> { Ok(Value::Bool(v)) }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> { Ok(Value::from(v)) }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> { Ok(Value::from(v)) }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> { Ok(Value::from(v)) }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        self.inspection.inspect(v, self.embedded_depth, true);
        Ok(if self.build { Value::String(v.to_owned()) } else { Value::Null })
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        self.inspection.inspect(&v, self.embedded_depth, true);
        Ok(if self.build { Value::String(v) } else { Value::Null })
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(LiteralSeed { inspection: &mut *self.inspection, embedded_depth: self.embedded_depth, build: self.build })? {
            if self.build { values.push(value); }
        }
        Ok(if self.build { Value::Array(values) } else { Value::Null })
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.inspection.inspect(&key, self.embedded_depth, false);
            let value = map.next_value_seed(LiteralSeed { inspection: &mut *self.inspection, embedded_depth: self.embedded_depth, build: self.build })?;
            if self.build { values.insert(key, value); }
        }
        Ok(if self.build { Value::Object(values) } else { Value::Null })
    }
}

fn literal_document(bytes: &[u8], inspection: &mut TokenInspection<'_>) -> Option<Value> {
    use serde::de::DeserializeSeed;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = (LiteralSeed { inspection, embedded_depth: 0, build: true }).deserialize(&mut decoder).ok()?;
    decoder.end().ok()?;
    Some(value)
}

fn token_inspection(token: &str) -> TokenInspection<'_> {
    TokenInspection { token, scan_decoded: true, echo: false, incomplete: false }
}

/// Does any JSON string literal of this body carry the token once decoded?
/// Duplicate members are all inspected: a parsed document keeps only the
/// last member, so the raw literals are the complete evidence.
fn decoded_strings_carry_token(body: &[u8], token: &str) -> bool {
    let mut index = 0;
    while index < body.len() {
        if body[index] != b'"' {
            index += 1;
            continue;
        }
        let Some((literal, next)) = decode_json_string_literal(body, index) else {
            index += 1;
            continue;
        };
        if net::carries_secret(literal.as_bytes(), token) {
            return true;
        }
        index = next;
    }
    false
}

/// Decode the JSON string literal that starts at `start`. The second value is
/// the offset after the literal. A literal that never closes is refused.
fn decode_json_string_literal(body: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor = start + 1;
    let mut decoded = String::new();
    while cursor < body.len() {
        match body[cursor] {
            b'"' => return Some((decoded, cursor + 1)),
            b'\\' => {
                cursor += 1;
                let escaped = *body.get(cursor)?;
                cursor += 1;
                match escaped {
                    b'"' => decoded.push('"'),
                    b'\\' => decoded.push('\\'),
                    b'/' => decoded.push('/'),
                    b'b' => decoded.push('\u{0008}'),
                    b'f' => decoded.push('\u{000c}'),
                    b'n' => decoded.push('\n'),
                    b'r' => decoded.push('\r'),
                    b't' => decoded.push('\t'),
                    b'u' => {
                        let mut code = 0u32;
                        let mut digits = 0;
                        while digits < 4 {
                            let digit = *body.get(cursor)?;
                            let value = (digit as char).to_digit(16)?;
                            code = code * 16 + value;
                            cursor += 1;
                            digits += 1;
                        }
                        decoded.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                    }
                    other => decoded.push(other as char),
                }
            }
            _ => {
                let start = cursor;
                while cursor < body.len() && body[cursor] != b'"' && body[cursor] != b'\\' {
                    cursor += 1;
                }
                decoded.push_str(&String::from_utf8_lossy(&body[start..cursor]));
            }
        }
    }
    None
}

/// Facts about one response body that both the projection and the shared
/// governor settlement must agree on.
struct ResponseFacts {
    /// The body carries the supplied bearer token, verbatim, percent-encoded,
    /// or inside a decoded JSON string.
    token_echo: bool,
    inspection_incomplete: bool,
    /// The body explicitly states that the session is not authenticated.
    session_denied: bool,
    /// The parsed JSON document, when the body is JSON at all. It is parsed
    /// exactly once and reused by the envelope parser.
    document: Option<Value>,
}

/// Inspect one response body once. The token is never echoed, so a body that
/// carries it is refused before any projection or export.
fn analyze_body(body: &[u8], token: &str) -> ResponseFacts {
    let mut facts = ResponseFacts {
        token_echo: false,
        inspection_incomplete: false,
        session_denied: false,
        document: None,
    };
    // Always examine the original, even for a short token or non-JSON body.
    // Continue parsing after an echo so session denial remains an independent
    // fact for the original lease. Without escapes, decoded literals are
    // already covered by the original scan; nested parsing still runs.
    let mut inspection = token_inspection(token);
    let raw_echo = net::carries_secret(body, token);
    inspection.echo = raw_echo;
    inspection.scan_decoded = !raw_echo && !token.is_empty() && body.contains(&b'\\');
    let document = literal_document(body, &mut inspection);
    facts.token_echo = raw_echo || (document.is_some() && inspection.echo)
        || (document.is_none() && inspection.scan_decoded && decoded_strings_carry_token(body, token));
    facts.inspection_incomplete = inspection.incomplete;
    if let Some(document) = document {
        facts.session_denied = session_denied_document(&document);
        facts.document = Some(document);
    }
    facts
}

/// Explicit application-level session-denial messages. The set is the one
/// already used by the sibling campus adapters; no upstream wording is
/// invented here and an ordinary business failure never matches.
const SESSION_DENIAL_MESSAGES: &[&str] = &[
    "请重新登录",
    "请先登录",
    "未登录",
    "登录失效",
    "登录已失效",
    "登录已过期",
    "会话已过期",
    "会话失效",
    "认证失败",
    "not logged in",
    "session expired",
    "unauthorized",
];

/// Is this message an explicit statement that the session is not
/// authenticated? The marker set is the one the sibling campus adapter
/// already uses for the same refusal. The message must be the refusal itself:
/// a marker that merely appears inside an unrelated business sentence, such
/// as "Duplicate title: session expired", is not an authentication refusal.
fn session_denial_message(message: &str) -> bool {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return false;
    }
    let is_marker = |part: &str| {
        SESSION_DENIAL_MESSAGES.iter().any(|marker| {
            if marker.is_ascii() {
                part.eq_ignore_ascii_case(marker)
            } else {
                part == *marker
            }
        })
    };
    if is_marker(trimmed) {
        return true;
    }
    // A refusal may carry a short trailing instruction, such as
    // "未登录，请重新登录". Every clause must itself be a refusal marker, so
    // an unrelated business subject never matches.
    let mut parts = trimmed.split(['，', ',', '；', ';']);
    parts.all(|part| {
        let part = part.trim();
        !part.is_empty() && is_marker(part)
    })
}

/// An explicit authentication refusal inside a `success=false` JSON
/// envelope. Only the envelope's own message members are inspected; an
/// ordinary business failure (no message, or an unrelated message) is not a
/// refusal.
fn session_denied_document(document: &Value) -> bool {
    let Some(root) = document.as_object() else {
        return false;
    };
    if !matches!(root.get("success"), Some(Value::Bool(false))) {
        return false;
    }
    ["message", "msg", "error", "error_message"]
        .iter()
        .filter_map(|key| root.get(*key))
        .filter_map(Value::as_str)
        .any(session_denial_message)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn unix_ms() -> Result<u64, Error> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| cache_error())?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| cache_error())
}

fn unix_seconds() -> Result<i64, Error> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| cache_error())?
        .as_secs();
    i64::try_from(seconds).map_err(|_| cache_error())
}

// ---------------------------------------------------------------------------
// Time handling
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Timestamp {
    Floating(NaiveDateTime),
    Offset(DateTime<FixedOffset>),
}

// A naive upstream date has no established timezone. Compare it only with
// another naive date; never invent an offset or discard fractional seconds.
fn parse_timestamp(value: &str) -> Option<Timestamp> {
    if let Ok(value) = DateTime::parse_from_rfc3339(value) {
        return Some(Timestamp::Offset(value));
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(value) = NaiveDateTime::parse_from_str(value, format) {
            return Some(Timestamp::Floating(value));
        }
    }
    None
}

fn compare_timestamps(left: &Timestamp, right: &Timestamp) -> Option<Ordering> {
    match (left, right) {
        (Timestamp::Floating(a), Timestamp::Floating(b)) => Some(a.cmp(b)),
        (Timestamp::Offset(a), Timestamp::Offset(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

/// Campus local hour (UTC+8), used only for the advisory idle-window hint.
fn campus_local_hour(epoch_seconds: i64) -> u32 {
    let local = epoch_seconds + 8 * 3600;
    let hour = local.rem_euclid(86_400) / 3600;
    hour as u32
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TokenSource {
    RedirectQueryToken,
    RedirectFragmentToken,
    CookieAppealPcToken,
}

impl TokenSource {
    fn label(self) -> &'static str {
        match self {
            Self::RedirectQueryToken => "redirect_query_token",
            Self::RedirectFragmentToken => "redirect_fragment_token",
            Self::CookieAppealPcToken => "cookie_appeal_pc_token",
        }
    }
}

#[derive(Debug)]
struct KnownItem {
    id: u64,
    status: String,
    reply_count: u32,
}
impl<'de> Deserialize<'de> for KnownItem {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {id:u64,status:String,reply_count:u32}
        let raw:Raw=deserialize_object(deserializer)?;
        Ok(Self{id:raw.id,status:raw.status,reply_count:raw.reply_count})
    }
}

struct ListInput {
    token: Option<Zeroizing<String>>,
    operation: Option<Operation>,
    token_source: Option<TokenSource>,
    limit: Option<u32>,
    page: Option<u32>,
    max_pages: Option<u32>,
    since_id: Option<u64>,
    since_time: Option<String>,
    known: Option<Vec<KnownItem>>,
    refresh: Option<bool>,
    download_attachments: Option<bool>,
}
impl<'de> Deserialize<'de> for ListInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self,D::Error> {
        // A positional array is not admitted by the documented object contract.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default, deserialize_with = "deserialize_optional_secret")]
            token: Option<Zeroizing<String>>,
            operation: Option<Operation>,
            token_source: Option<TokenSource>,
            limit: Option<u32>,
            page: Option<u32>,
            max_pages: Option<u32>,
            since_id: Option<u64>,
            since_time: Option<String>,
            known: Option<Vec<KnownItem>>,
            refresh: Option<bool>,
            download_attachments: Option<bool>,
        }
        let raw:Raw=deserialize_object(deserializer)?;
        Ok(Self{token:raw.token,operation:raw.operation,token_source:raw.token_source,limit:raw.limit,page:raw.page,max_pages:raw.max_pages,since_id:raw.since_id,since_time:raw.since_time,known:raw.known,refresh:raw.refresh,download_attachments:raw.download_attachments})
    }
}

struct DetailInput {
    token: Option<Zeroizing<String>>,
    operation: Option<Operation>,
    token_source: Option<TokenSource>,
    id: u64,
    refresh: Option<bool>,
    download_attachments: Option<bool>,
}
impl<'de> Deserialize<'de> for DetailInput {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default,deserialize_with="deserialize_optional_secret")]
            token:Option<Zeroizing<String>>,operation:Option<Operation>,token_source:Option<TokenSource>,
            id:u64,refresh:Option<bool>,download_attachments:Option<bool>,
        }
        let raw:Raw=deserialize_object(deserializer)?;
        Ok(Self{token:raw.token,operation:raw.operation,token_source:raw.token_source,id:raw.id,refresh:raw.refresh,download_attachments:raw.download_attachments})
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    List,
    Detail,
}

// Ignored fields are consumed by serde's IgnoredAny path, not materialized
// into Value or copied into a serialized request. The second typed parse
// enforces the selected operation's complete deny_unknown_fields contract.
struct OperationSelector {
    operation: Operation,
}
impl<'de> Deserialize<'de> for OperationSelector {
    fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
        #[derive(Deserialize)]
        struct Raw {operation:Operation}
        let raw:Raw=deserialize_object(deserializer)?;
        Ok(Self{operation:raw.operation})
    }
}

/// Enforce object shape before typed field decoding; Raw helpers, not the
/// outer types, are delegated through MapAccessDeserializer to avoid recursion.
fn deserialize_object<'de,D,T>(deserializer:D)->Result<T,D::Error>
where D:serde::Deserializer<'de>, T:Deserialize<'de> {
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de,T:Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value=T;
        fn expecting(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("a JSON object")}
        fn visit_map<A:serde::de::MapAccess<'de>>(self,map:A)->Result<T,A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
}

fn deserialize_optional_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    struct Secret(Zeroizing<String>);
    impl<'de> Deserialize<'de> for Secret {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            String::deserialize(deserializer).map(|value| Secret(Zeroizing::new(value)))
        }
    }
    Option::<Secret>::deserialize(deserializer).map(|secret| secret.map(|secret| secret.0))
}

struct ListRequest {
    token: Zeroizing<String>,
    token_source: Option<TokenSource>,
    limit: u32,
    page: u32,
    max_pages: u32,
    since_id: Option<u64>,
    since_time_raw: Option<String>,
    since_time: Option<Timestamp>,
    known: BTreeMap<u64, KnownItem>,
    refresh: bool,
}

struct DetailRequest {
    token: Zeroizing<String>,
    token_source: Option<TokenSource>,
    id: u64,
    refresh: bool,
}

/// A bearer token is opaque, but it must be safe to place in one header value:
/// visible ASCII only, no whitespace, no control characters, bounded length.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn parse_list_input(input: &str) -> Result<ListRequest, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid_input("the ihome request is too large"));
    }
    let mut parsed: ListInput =
        serde_json::from_str(input).map_err(|_| invalid_input("the ihome request is invalid"))?;
    if parsed.operation.is_some_and(|operation| operation != Operation::List) {
        return Err(invalid_input("the ihome operation must be list"));
    }
    let token = parsed.token.take().ok_or_else(token_required)?;
    if !valid_token(token.as_str()) {
        return Err(token_required());
    }
    if parsed.download_attachments == Some(true) {
        return Err(attachment_download_unsupported());
    }
    let limit = parsed.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(invalid_input("limit must be between 1 and 100"));
    }
    let page = parsed.page.unwrap_or(1);
    if !(1..=MAX_PAGE).contains(&page) {
        return Err(invalid_input("page is outside the supported pagination range"));
    }
    let max_pages = parsed.max_pages.unwrap_or(DEFAULT_PAGES);
    if !(1..=MAX_PAGES).contains(&max_pages) {
        return Err(invalid_input("max_pages must be between 1 and 20"));
    }
    let mut since_time = None;
    let since_time_raw = parsed.since_time.take();
    if let Some(raw) = since_time_raw.as_deref() {
        let parsed_time = parse_timestamp(raw)
            .ok_or_else(|| invalid_input("since_time is not a parsable timestamp"))?;
        since_time = Some(parsed_time);
    }
    let mut known = BTreeMap::new();
    if let Some(items) = parsed.known.take() {
        if items.len() > MAX_KNOWN_ITEMS {
            return Err(invalid_input("known carries too many items"));
        }
        for item in items {
            if known.insert(item.id, item).is_some() {
                return Err(invalid_input("known carries a duplicate id"));
            }
        }
    }
    Ok(ListRequest {
        token,
        token_source: parsed.token_source,
        limit,
        page,
        max_pages,
        since_id: parsed.since_id,
        since_time_raw,
        since_time,
        known,
        refresh: parsed.refresh.unwrap_or(false),
    })
}

fn parse_detail_input(input: &str) -> Result<DetailRequest, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid_input("the ihome request is too large"));
    }
    let mut parsed: DetailInput =
        serde_json::from_str(input).map_err(|_| invalid_input("the ihome request is invalid"))?;
    if parsed.operation.is_some_and(|operation| operation != Operation::Detail) {
        return Err(invalid_input("the ihome operation must be detail"));
    }
    let token = parsed.token.take().ok_or_else(token_required)?;
    if !valid_token(token.as_str()) {
        return Err(token_required());
    }
    if parsed.download_attachments == Some(true) {
        return Err(attachment_download_unsupported());
    }
    Ok(DetailRequest {
        token,
        token_source: parsed.token_source,
        id: parsed.id,
        refresh: parsed.refresh.unwrap_or(false),
    })
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

fn list_url(limit: u32, page: u32) -> Result<Url, Error> {
    let mut url = Url::parse(IHOME_ORIGIN).map_err(|_| invalid_url())?;
    url.set_path(IHOME_API_PATH);
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &limit.to_string());
        query.append_pair("page", &page.to_string());
    }
    Ok(url)
}

fn detail_url(id: u64) -> Result<Url, Error> {
    let mut url = Url::parse(IHOME_ORIGIN).map_err(|_| invalid_url())?;
    url.set_path(&format!("{IHOME_API_PATH}/{id}"));
    Ok(url)
}

/// Only the two documented read endpoints on the platform host are admitted.
fn allowed_url(url: &Url) -> bool {
    if url.scheme() != "https"
        || url.host_str() != Some(IHOME_HOST)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let path = url.path();
    if path == IHOME_API_PATH {
        return true;
    }
    let Some(id) = path.strip_prefix(IHOME_DETAIL_PREFIX) else { return false; };
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    version: u8,
    url: String,
    status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
    sha256: String,
    fetched_at_unix_ms: u64,
    challenge: bool,
}

struct ResponseCache {
    directory: File,
}

impl ResponseCache {
    /// The cache directory is scoped by a one-way hash of the bearer token so
    /// two credentials never share private response bodies.
    fn open(scope: &str) -> Result<Self, Error> {
        let home = governor::identity_home().map_err(|_| cache_error())?;
        let _home = governor::open_directory(&home, false, false).map_err(|_| cache_error())?;
        let base = home.join(CACHE_DIR);
        let _base = governor::open_directory(&base, true, true).map_err(|_| cache_error())?;
        let directory = governor::open_directory(&base.join(scope), true, true)
            .map_err(|_| cache_error())?;
        Ok(Self { directory })
    }

    fn validate_directory(&self) -> Result<(), Error> {
        let metadata = self.directory.metadata().map_err(|_| cache_error())?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(cache_error());
        }
        Ok(())
    }

    fn name(url: &Url) -> String {
        format!("{}.json", sha256(url.as_str().as_bytes()))
    }

    fn load(&self, url: &Url) -> Result<Option<(Response, ChallengeAssessment)>, Error> {
        self.validate_directory()?;
        let file = match governor::open_child(&self.directory, &Self::name(url), libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(cache_error()),
        };
        governor::validate_private_file(&file).map_err(|_| corrupt_cache())?;
        let mut bytes = Vec::new();
        file.take(MAX_CACHE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| cache_error())?;
        if bytes.len() as u64 > MAX_CACHE_BYTES {
            return Err(corrupt_cache());
        }
        let cached: Cached = serde_json::from_slice(&bytes).map_err(|_| corrupt_cache())?;
        if !matches!(cached.version, 2 | 3 | 4)
            || cached.url != url.as_str()
            || !(100..=999).contains(&cached.status)
            || !valid_sha256(&cached.sha256)
            || cached.body_base64.len() > MAX_BODY.div_ceil(3) * 4
            || cached.headers.iter().any(|(name, value)| {
                !HEADER_NAMES.contains(&name.as_str()) || !valid_header(value)
            })
        {
            return Err(corrupt_cache());
        }
        let body = STANDARD
            .decode(&cached.body_base64)
            .map_err(|_| corrupt_cache())?;
        if body.len() > MAX_BODY || sha256(&body) != cached.sha256 {
            return Err(corrupt_cache());
        }
        let body_assessment = assess_response_body(&body, cached.headers.get("content-type").map(String::as_str), true);
        // Version 2's broad substring flag did not retain whether a header or
        // body caused it. Preserve its refusal, not an unproved CAPTCHA claim.
        let challenge = if cached.challenge && cached.version >= 3 {
            ChallengeAssessment::Detected
        } else if cached.challenge && !matches!(body_assessment, ChallengeAssessment::Detected) {
            ChallengeAssessment::Unreviewed
        } else {
            body_assessment
        };
        let cookie_reviewed = cached.version == 4;
        let response = Response {
            url: cached.url,
            status: cached.status,
            headers: cached.headers,
            body,
            sha256: cached.sha256,
            fetched_at_unix_ms: cached.fetched_at_unix_ms,
            cache_status: CacheStatus::Hit,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        if !cookie_reviewed {
            // Earlier writers discarded Set-Cookie. Keep the original file,
            // but do not publish its body or automatically re-fetch it.
            let facts = analyze_body(&response.body, "");
            if cached_rejection(&response, &challenge, &facts) {
                return Err(Error::new("safety_latched", "a retained safety observation prevents this result"));
            }
            return Err(Error::new("cached_response_unreviewed", "retained response predates cookie admission; original preserved and body withheld"));
        }
        Ok(Some((response, challenge)))
    }

    fn save(&self, response: &Response, challenge: &ChallengeAssessment) -> Result<(), Error> {
        self.validate_directory()?;
        let url = Url::parse(&response.url).map_err(|_| invalid_url())?;
        let name = Self::name(&url);
        match governor::open_child(&self.directory, &name, libc::O_RDONLY) {
            Ok(existing) => {
                governor::validate_private_file(&existing).map_err(|_| cache_error())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(cache_error()),
        }
        let stored = Cached {
            version: 4,
            url: response.url.clone(),
            status: response.status,
            headers: response.headers.clone(),
            body_base64: STANDARD.encode(&response.body),
            sha256: response.sha256.clone(),
            fetched_at_unix_ms: response.fetched_at_unix_ms,
            challenge: matches!(challenge, ChallengeAssessment::Detected),
        };
        let (temporary_name, mut temporary) =
            governor::create_temporary(&self.directory).map_err(|_| cache_error())?;
        let result = (|| {
            governor::validate_private_file(&temporary).map_err(|_| cache_error())?;
            serde_json::to_writer(&mut temporary, &stored).map_err(|_| cache_error())?;
            temporary.write_all(b"\n").map_err(|_| cache_error())?;
            temporary.sync_all().map_err(|_| cache_error())?;
            let target = CString::new(name).map_err(|_| cache_error())?;
            // SAFETY: both names are single components in this pinned directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    self.directory.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err(cache_error());
            }
            self.directory.sync_all().map_err(|_| cache_error())
        })();
        if result.is_err() {
            // SAFETY: this is our exclusively created temporary, not user input.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), temporary_name.as_ptr(), 0);
            }
        }
        result
    }

    /// Remove one cached entry. A cached body that echoes the submitted
    /// bearer token must not stay on disk.
    fn remove(&self, url: &Url) -> Result<(), Error> {
        self.validate_directory()?;
        match governor::open_child(&self.directory, &Self::name(url), libc::O_RDONLY) {
            Ok(existing) => {
                governor::validate_private_file(&existing).map_err(|_| cache_error())?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(_) => return Err(cache_error()),
        }
        let name = Self::name(url);
        let target = CString::new(name).map_err(|_| cache_error())?;
        // SAFETY: both names are single components in this pinned directory.
        if unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), target.as_ptr(), 0)
        } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        {
            return Err(cache_error());
        }
        self.directory.sync_all().map_err(|_| cache_error())
    }

    /// Cache-first read. A hit never sends a request; a confirmed cached
    /// challenge or rejection is refused without manufacturing a new HTTP observation.
    fn get<T>(
        &self,
        url: &Url,
        token: &str,
        online: bool,
        refresh: bool,
        process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if refresh && !online {
            return Err(invalid_input("refresh requires online authorization"));
        }
        if !refresh {
            if let Some((response, challenge)) = self.load(url)? {
                let facts = analyze_body(&response.body, token);
                if facts.token_echo {
                    // A cached body that echoes the submitted token is never
                    // published and never kept on disk.
                    self.remove(url)?;
                }
                if cached_rejection(&response, &challenge, &facts) {
                    // A cached HTTP authentication rejection and a cached
                    // application-level refusal must never be replayed as an
                    // ordinary result.
                    return Err(Error::new("safety_latched", "a retained safety observation prevents this result"));
                }
                if facts.inspection_incomplete {
                    return Err(Error::new("response_unreviewed", "response content withheld because token inspection was incomplete"));
                }
                return process(&response, &challenge, &facts);
            }
        }
        if !online {
            return Err(Error::new(
                "offline_miss",
                "the ihome response is not in the private cache",
            ));
        }
        Transport::open()?.fetch(self, url, token, refresh, process)
    }


}

fn valid_header(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

struct Transport {
    governor: Governor,
    http: Client,
}

impl Transport {
    fn open() -> Result<Self, Error> {
        let governor = Governor::open().map_err(|_| governor_error())?;
        Ok(Self { governor, http: Self::client()? })
    }

    /// Unit-process fixture transport bound to an isolated governor directory.
    /// No request is sent unless the bounded cache misses.
    #[cfg(test)]
    fn open_isolated(governor: Governor) -> Result<Self, Error> {
        Ok(Self { governor, http: Self::client()? })
    }

    fn client() -> Result<Client, Error> {
        let http = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .user_agent("buaa-cli/0.1 ihome")
            .build()
            .map_err(|_| Error::new(
                "transport_unavailable",
                "cannot initialize the ihome transport",
            ))?;
        Ok(http)
    }

    /// One request, one shared lease. The lease is held until the body has
    /// been read and structured, and is settled with the observed status and
    /// `Retry-After`. No retry is attempted, ever.
    fn fetch<T>(
        &self,
        cache: &ResponseCache,
        url: &Url,
        token: &str,
        refresh: bool,
        process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !allowed_url(url) {
            return Err(invalid_url());
        }
        let credential = Zeroizing::new(format!("Bearer {token}"));
        let mut authorization =
            reqwest::header::HeaderValue::from_bytes(credential.as_bytes())
                .map_err(|_| invalid_input("the bearer token cannot be sent as a header"))?;
        authorization.set_sensitive(true);
        let request = self
            .http
            .get(url.clone())
            .header("Accept-Encoding", "identity")
            .header("Accept", "application/json")
            .header("Referer", IHOME_REFERER)
            .header(reqwest::header::AUTHORIZATION, authorization)
            // The builder timeout resets after every socket read; bind an equal
            // per-request deadline to this actual request instead.
            .timeout(Duration::from_secs(45));
        let mut lease = net::acquire(&self.governor)?;
        if !refresh {
            match cache.load(url) {
                Ok(Some((response, challenge))) => {
                    let facts = analyze_body(&response.body, token);
                    if facts.token_echo {
                        // A cached body that echoes the submitted token is
                        // never published and never kept on disk.
                        cache.remove(url).map_err(|_| governor_error())?;
                    }
                    // The cached hit carries the request to completion with no
                    // network access; settle the lease without a request.
                    lease.finish_without_request().map_err(|_| governor_error())?;
                    if facts.inspection_incomplete {
                        return Err(Error::new("response_unreviewed", "response content withheld because token inspection was incomplete"));
                    }
                    return process(&response, &challenge, &facts);
                }
                Ok(None) => {}
                Err(error) => {
                    lease.finish_without_request().map_err(|_| governor_error())?;
                    return Err(error);
                }
            }
        }
        let mut raw = match lease.start_request(||request.send()) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| governor_error())?;
                return Err(network_error());
            }
            Err(governor::FollowupError::Governor(_)) => return Err(governor_error()),
        };
        let status = raw.status().as_u16();
        let issues_session_cookie = net::issues_session_cookie(raw.headers());
        let retry_after = raw
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let header_challenge = raw
            .headers()
            .iter()
            .any(|(name, value)| net::challenge_header(name.as_str(), value.as_bytes()));
        // Persist every observed cooldown before header collection or body
        // handling can fail; retain the same pending request and original lock.
        observe_response_headers(&mut lease,status,raw.headers(),header_challenge)?;
        let mut challenge = if header_challenge {
            ChallengeAssessment::Detected
        } else {
            ChallengeAssessment::Unreviewed
        };
        let mut facts = ResponseFacts {
            token_echo: false,
            inspection_incomplete: false,
            session_denied: false,
            document: None,
        };
        let result = (|| {
            if raw
                .content_length()
                .is_some_and(|length| length > MAX_BODY as u64)
            {
                return Err(body_limit());
            }
            let headers = collect_headers(raw.headers())?;
            let mut body = Vec::new();
            let read = raw.by_ref()
                .take(MAX_BODY as u64 + 1)
                .read_to_end(&mut body);
            let assessment = assess_response_body(
                &body,
                headers.get("content-type").map(String::as_str),
                read.is_ok() && body.len() <= MAX_BODY,
            );
            challenge = if header_challenge { ChallengeAssessment::Detected } else { assessment };
            read.map_err(|_| network_error())?;
            if body.len() > MAX_BODY {
                return Err(body_limit());
            }
            let response = Response {
                url: url.as_str().to_owned(),
                status,
                headers,
                sha256: sha256(&body),
                body,
                fetched_at_unix_ms: unix_ms()?,
                cache_status: CacheStatus::Miss,
                revalidated_at_unix_ms: None,
                revalidation_status: None,
            };
            facts = analyze_body(&response.body, token);
            admit_response(cache, &response, &challenge, &facts, issues_session_cookie, process)
        })();
        let network_failure = result
            .as_ref()
            .is_err_and(|error| error.code == "network_error");
        drop(raw);
        // An explicit application-level authentication refusal is a credential
        // rejection, not an ordinary HTTP success. The already-observed
        // Retry-After stays durable in the lease state.
        let outcome = if facts.session_denied {
            Outcome::CredentialRejected
        } else {
            Outcome::Http {
                status,
                retry_after: retry_after.as_deref(),
                challenge: matches!(challenge, ChallengeAssessment::Detected),
                network_failure,
            }
        };
        lease
            .finish(outcome)
            .map_err(|_| governor_error())?;
        result
    }
}

// Only a cookie-reviewed original reaches the version-4 writer. Older cache
// files are retained for private recovery, not replayed as admitted bodies.
fn admit_response<T>(
    cache: &ResponseCache,
    response: &Response,
    challenge: &ChallengeAssessment,
    facts: &ResponseFacts,
    issues_session_cookie: bool,
    process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts) -> Result<T, Error>,
) -> Result<T, Error> {
    if issues_session_cookie {
        return Err(Error::new("session_cookie_issued", "response content withheld because upstream issued a session cookie"));
    }
    if facts.inspection_incomplete {
        return Err(Error::new("response_unreviewed", "response content withheld because token inspection was incomplete"));
    }
    let processed = process(response, challenge, facts)?;
    if !facts.token_echo {
        cache.save(response, challenge)?;
    }
    Ok(processed)
}

fn observe_response_headers(lease:&mut governor::RequestLease<'_>,status:u16,headers:&reqwest::header::HeaderMap,challenge:bool)->Result<(),Error> {
    lease.observe_http_many(status,headers.get_all("retry-after").iter().map(|value|value.to_str().ok()),challenge)
        .map_err(|_|governor_error())
}

fn collect_headers(headers: &reqwest::header::HeaderMap) -> Result<BTreeMap<String, String>, Error> {
    let mut collected = BTreeMap::new();
    let mut total = 0usize;
    for name in HEADER_NAMES {
        let mut values = headers.get_all(*name).iter();
        let Some(first) = values.next() else {
            continue;
        };
        let mut value = first
            .to_str()
            .map_err(|_| Error::new("invalid_headers", "the ihome response headers are invalid"))?
            .to_owned();
        for next in values {
            value.push_str(", ");
            value.push_str(next.to_str().map_err(|_| {
                Error::new("invalid_headers", "the ihome response headers are invalid")
            })?);
        }
        if !valid_header(&value) {
            return Err(Error::new(
                "invalid_headers",
                "the ihome response headers are invalid",
            ));
        }
        total = total
            .checked_add(name.len() + value.len())
            .ok_or_else(|| {
                Error::new("invalid_headers", "the ihome response headers are invalid")
            })?;
        if total > MAX_HEADERS {
            return Err(Error::new(
                "invalid_headers",
                "the ihome response headers are invalid",
            ));
        }
        collected.insert((*name).to_owned(), value);
    }
    Ok(collected)
}

/// Header collection retains duplicate fields privately as a comma-joined
/// value. Such a Content-Type cannot establish body admission, including on
/// cache replay. A positive shared challenge observation still takes priority.
fn assess_response_body(bytes:&[u8], mime:Option<&str>, complete:bool)->ChallengeAssessment {
    if mime.is_some_and(|value|value.contains(',')) {
        return match assess_challenge_body(bytes,None,complete) {
            ChallengeAssessment::Detected=>ChallengeAssessment::Detected,
            _=>ChallengeAssessment::Unreviewed,
        };
    }
    assess_challenge_body(bytes,mime,complete)
}

/// An upstream header value that is projected into output is withheld when it
/// carries the submitted credential. MIME essence and parameters are
/// untrusted text: the submitted bearer can appear as a type, a parameter, or
/// any of its reversible spellings (verbatim, percent/form-decoded or base64),
/// and the projected lowercase essence must not leak it either. A spurious
/// short-token match only withholds a header fact; it can never disclose one.
fn credential_value_carries_token(value: &str, token: &str) -> bool {
    !token.is_empty()
        && (net::carries_secret(value.as_bytes(), token)
            || net::carries_secret(
                value.to_ascii_lowercase().as_bytes(),
                &token.to_ascii_lowercase(),
            ))
}

fn content_type(response: &Response, token: &str) -> Option<String> {
    let raw = response.headers.get("content-type")?;
    if credential_value_carries_token(raw, token) {
        return None;
    }
    let essence = raw.split(';').next()?.trim();
    let (kind, subtype) = essence.split_once('/')?;
    let token = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'!'|b'#'|b'$'|b'&'|b'^'|b'_'|b'.'|b'+'|b'-'));
    (token(kind) && token(subtype)).then(|| essence.to_ascii_lowercase())
}

/// The projected `content_type` is `null` whenever a header value was present
/// but not fully projected: parameters withheld, a malformed value, or a value
/// that carries the submitted credential.
fn content_type_parameters_withheld(response: &Response, token: &str) -> bool {
    response.headers.get("content-type").is_some_and(|value| {
        credential_value_carries_token(value, token)
            || value.contains(';')
            || content_type(response, token).is_none()
    })
}

fn credential_key(key: &str) -> bool {
    let normalized: String = key
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte|byte.to_ascii_lowercase() as char)
        .collect();
    ["password","passwd","token","cookie","authorization","secret","session","ticket","execution","credential","csrf","jwt"]
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn credential_url(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
        || url.query_pairs().any(|(key,_)|credential_key(&key))
        || url.fragment().is_some()
}

/// Inspect an untrusted URL-like string without granting it attachment-fetch
/// authority. Relative references are inspected, never resolved or fetched.
fn credential_reference(text: &str) -> bool {
    if let Some(rest) = text
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
        .map(|_| &text[7..])
    {
        let token: String = rest
            .chars()
            .take_while(|character| !character.is_whitespace())
            .collect();
        return looks_like_bearer_credential(&token);
    }
    if text.contains("://") {
        return Url::parse(text).map_or(true, |url| credential_url(&url));
    }
    let candidate = if text.starts_with("//") {
        format!("https:{text}")
    } else if text.starts_with('/') {
        format!("https://placeholder.invalid{text}")
    } else {
        // A bare reference may still carry a credential-bearing query key.
        return text
            .split_once('=')
            .is_some_and(|(key, _)| credential_key(key));
    };
    Url::parse(&candidate).map_or(true, |url| credential_url(&url))
}

/// A bearer credential in any body form, including a MIME that does not claim
/// JSON. Ordinary prose without a credential-shaped token stays admissible.
fn bearer_credential_present(bytes: &[u8]) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut cursor = source.as_bytes();
    while let Some(position) = cursor.windows(7).position(|window| {
        window.eq_ignore_ascii_case(b"bearer ")
    }) {
        let rest = &cursor[position + 7..];
        let token: String = rest
            .iter()
            .take_while(|byte| !byte.is_ascii_whitespace())
            .map(|byte| *byte as char)
            .collect();
        if looks_like_bearer_credential(&token) {
            return true;
        }
        cursor = &cursor[position + 7..];
    }
    false
}

/// A bearer credential is a long opaque token, not an ordinary English word
/// that happens to follow the word "bearer" in upstream prose.
fn looks_like_bearer_credential(token: &str) -> bool {
    if token.len() < 8 {
        return false;
    }
    token.len() >= 20 || token.bytes().any(|byte| !byte.is_ascii_alphabetic())
}

// Streaming inspection visits every duplicate map member and decodes escaped
// keys before classification; Value would silently discard duplicate members.
struct JsonSafetySeed { depth: usize }
impl<'de> serde::de::DeserializeSeed<'de> for JsonSafetySeed {
    type Value = bool;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<bool,D::Error> {
        if self.depth > 32 { return Err(serde::de::Error::custom("response nesting exceeds safe inspection")); }
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for JsonSafetySeed {
    type Value = bool;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str("a JSON response value") }
    fn visit_bool<E: serde::de::Error>(self,_: bool)->Result<bool,E>{Ok(false)}
    fn visit_i64<E: serde::de::Error>(self,_: i64)->Result<bool,E>{Ok(false)}
    fn visit_u64<E: serde::de::Error>(self,_: u64)->Result<bool,E>{Ok(false)}
    fn visit_f64<E: serde::de::Error>(self,_: f64)->Result<bool,E>{Ok(false)}
    fn visit_unit<E: serde::de::Error>(self)->Result<bool,E>{Ok(false)}
    fn visit_str<E: serde::de::Error>(self,value: &str)->Result<bool,E>{
        let text=value.trim();
        if text.starts_with(['{','[']) {
            return Ok(json_contains_credentials(text.as_bytes(),self.depth+1));
        }
        // A JSON string can itself be another complete JSON document. Recurse
        // under the same depth budget so escaping cannot hide credential keys.
        if text.starts_with('"') {
            return Ok(json_contains_credentials(text.as_bytes(),self.depth+1));
        }
        Ok(credential_reference(text))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self,mut seq:A)->Result<bool,A::Error>{
        let mut unsafe_value=false;
        while let Some(nested)=seq.next_element_seed(JsonSafetySeed{depth:self.depth+1})? { unsafe_value |= nested; }
        Ok(unsafe_value)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self,mut map:A)->Result<bool,A::Error>{
        let mut unsafe_value=false;
        while let Some(key)=map.next_key::<String>()? {
            unsafe_value |= credential_key(&key);
            unsafe_value |= map.next_value_seed(JsonSafetySeed{depth:self.depth+1})?;
        }
        Ok(unsafe_value)
    }
}
fn json_contains_credentials(bytes:&[u8],depth:usize)->bool {
    use serde::de::DeserializeSeed;
    let mut decoder=serde_json::Deserializer::from_slice(bytes);
    match (JsonSafetySeed{depth}).deserialize(&mut decoder) {
        Ok(unsafe_value)=>unsafe_value || decoder.end().is_err(),
        Err(_)=>true,
    }
}

// ---------------------------------------------------------------------------
// Upstream structure
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FallbackReason {
    UnexpectedContent,
    UpstreamParse,
    UpstreamShape,
    RateLimited,
    SafetyLatched,
    ChallengeUnreviewed,
    RedirectRefused,
    HttpRejected,
    UnsupportedEncoding,
    IncomparableTimestamp,
    /// An explicit application-level statement that the session is not
    /// authenticated. This is distinct from an ordinary business failure.
    AuthenticationRefused,
    /// The response body echoes the submitted bearer token. Nothing from
    /// such a body is projected or exported.
    CredentialEcho,
    InspectionUnreviewed,
}

impl FallbackReason {
    fn code(self) -> &'static str {
        match self {
            Self::UnexpectedContent => "unexpected_content",
            Self::UpstreamParse => "upstream_parse",
            Self::UpstreamShape => "upstream_shape",
            Self::RateLimited => "rate_limited",
            Self::SafetyLatched => "safety_latched",
            Self::ChallengeUnreviewed => "challenge_unreviewed",
            Self::RedirectRefused => "redirect_refused",
            Self::HttpRejected => "http_rejected",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::IncomparableTimestamp => "incomparable_timestamp",
            Self::AuthenticationRefused => "authentication_refused",
            Self::CredentialEcho => "credential_echo",
            Self::InspectionUnreviewed => "inspection_unreviewed",
        }
    }
}

fn response_refusal(response: &Response, challenge: &ChallengeAssessment) -> Option<FallbackReason> {
    if matches!(challenge, ChallengeAssessment::Detected) || matches!(response.status, 401 | 403) {
        return Some(FallbackReason::SafetyLatched);
    }
    if matches!(challenge, ChallengeAssessment::Unreviewed) {
        return Some(FallbackReason::ChallengeUnreviewed);
    }
    if response.status == 429 {
        return Some(FallbackReason::RateLimited);
    }
    if (300..400).contains(&response.status) {
        return Some(FallbackReason::RedirectRefused);
    }
    if response.status != 200 {
        return Some(FallbackReason::HttpRejected);
    }
    if response.headers.get("content-encoding").is_some_and(|encoding| {
        !encoding.eq_ignore_ascii_case("identity")
    }) {
        return Some(FallbackReason::UnsupportedEncoding);
    }
    None
}

/// A cached response that is an authentication rejection must be published to
/// the shared governor, exactly like a confirmed challenge. Otherwise an
/// explicit resume clears the original live rejection and the same cached
/// rejection is replayed with no safety observation at all.
fn cached_rejection(
    response: &Response,
    challenge: &ChallengeAssessment,
    facts: &ResponseFacts,
) -> bool {
    matches!(challenge, ChallengeAssessment::Detected)
        || matches!(response.status, 401 | 403)
        || facts.session_denied
}

fn json_mime(value: &str) -> bool {
    let mime = value.split(';').next().unwrap_or("").trim();
    mime.eq_ignore_ascii_case("application/json")
        || mime.eq_ignore_ascii_case("text/json")
        || mime.as_bytes().get(mime.len().saturating_sub(5)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b"+json"))
}

struct Reply {
    id: u64,
    department_id: u64,
    department_name: String,
    content: String,
    created_at: String,
}

struct Entry {
    id: u64,
    title: String,
    content: String,
    created_at: String,
    status: String,
    replies: Vec<Reply>,
    departments: Vec<(u64, String)>,
    attachments: Vec<String>,
}

fn required_str(item: &Map<String, Value>, key: &str) -> Result<String, FallbackReason> {
    match item.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(FallbackReason::UpstreamShape),
    }
}

fn required_u64(item: &Map<String, Value>, key: &str) -> Result<u64, FallbackReason> {
    match item.get(key) {
        Some(Value::Number(number)) => number.as_u64().ok_or(FallbackReason::UpstreamShape),
        _ => Err(FallbackReason::UpstreamShape),
    }
}

fn required_array<'a>(
    item: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a [Value], FallbackReason> {
    match item.get(key) {
        None => Err(FallbackReason::UpstreamShape),
        Some(Value::Array(items)) => Ok(items.as_slice()),
        Some(_) => Err(FallbackReason::UpstreamShape),
    }
}

fn parse_department(value: &Value) -> Result<(u64, String), FallbackReason> {
    let map = value.as_object().ok_or(FallbackReason::UpstreamShape)?;
    Ok((
        required_u64(map, "id")?,
        required_str(map, "name")?,
    ))
}

fn parse_reply(value: &Value) -> Result<Reply, FallbackReason> {
    let map = value.as_object().ok_or(FallbackReason::UpstreamShape)?;
    let department = map
        .get("department")
        .and_then(Value::as_object)
        .ok_or(FallbackReason::UpstreamShape)?;
    let content = required_str(map, "content")?;
    if content.len() > MAX_REPLY_CONTENT_BYTES {
        return Err(FallbackReason::UpstreamShape);
    }
    Ok(Reply {
        id: required_u64(map, "id")?,
        department_id: required_u64(department, "id")?,
        department_name: required_str(department, "name")?,
        content,
        created_at: required_str(map, "created_at")?,
    })
}

/// Collect absolute HTTP(S) URLs that the upstream record itself declares.
///
/// Only an exact absolute URL, or an absolute URL inside a declared
/// structured field (object, array, or a JSON-encoded object/array), is
/// collected. Relative references are ignored rather than resolved against a
/// guessed host, free text is never scanned for embedded links, and nothing
/// is ever fetched.
fn collect_declared_urls(value: &Value, out: &mut Vec<String>, depth: usize) {
    if depth > 4 || out.len() >= MAX_ATTACHMENTS_PER_ENTRY {
        return;
    }
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_ATTACHMENT_URL_BYTES {
                return;
            }
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                if let Some(decoded) = literal_document(trimmed.as_bytes(), &mut token_inspection("")) {
                    collect_declared_urls(&decoded, out, depth + 1);
                    return;
                }
            }
            let Ok(url) = Url::parse(trimmed) else {
                return;
            };
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || credential_url(&url) {
                return;
            }
            if !out.iter().any(|existing| existing.as_str() == trimmed) {
                out.push(trimmed.to_owned());
            }
        }
        Value::Object(map) => {
            for nested in map.values() {
                collect_declared_urls(nested, out, depth + 1);
            }
        }
        Value::Array(items) => {
            for nested in items {
                collect_declared_urls(nested, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn parse_entry(value: &Value) -> Result<Entry, FallbackReason> {
    let map = value.as_object().ok_or(FallbackReason::UpstreamShape)?;
    let content = required_str(map, "content")?;
    if content.len() > MAX_CONTENT_BYTES {
        return Err(FallbackReason::UpstreamShape);
    }
    let mut departments = Vec::new();
    for department in required_array(map, "departments")? {
        if departments.len() >= MAX_DEPARTMENTS_PER_ENTRY {
            return Err(FallbackReason::UpstreamShape);
        }
        departments.push(parse_department(department)?);
    }
    let mut replies = Vec::new();
    for reply in required_array(map, "appeal_reply")? {
        if replies.len() >= MAX_REPLIES_PER_ENTRY {
            return Err(FallbackReason::UpstreamShape);
        }
        replies.push(parse_reply(reply)?);
    }
    let mut attachments = Vec::new();
    for field in ATTACHMENT_FIELDS {
        if let Some(declared) = map.get(*field) {
            collect_declared_urls(declared, &mut attachments, 0);
        }
    }
    Ok(Entry {
        id: required_u64(map, "id")?,
        title: required_str(map, "title")?,
        content,
        created_at: required_str(map, "created_at")?,
        status: required_str(map, "publish_status_text")?,
        replies,
        departments,
        attachments,
    })
}

/// Parse the upstream envelope. `success=false` is an empty listing, not a
/// fault; every other deviation is reported with its own fallback reason.
/// The document is decoded once by the caller and reused here.
fn parse_envelope(
    mime: Option<&str>,
    document: Option<&Value>,
) -> Result<(bool, Vec<Entry>), FallbackReason> {
    if let Some(mime) = mime {
        if !json_mime(mime) {
            return Err(FallbackReason::UnexpectedContent);
        }
    }
    let document = document.ok_or(FallbackReason::UpstreamParse)?;
    let root = document.as_object().ok_or(FallbackReason::UpstreamShape)?;
    let success = match root.get("success") {
        Some(Value::Bool(value)) => *value,
        _ => return Err(FallbackReason::UpstreamShape),
    };
    if !success {
        return Ok((false, Vec::new()));
    }
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or(FallbackReason::UpstreamShape)?;
    let items = data
        .get("data")
        .and_then(Value::as_array)
        .ok_or(FallbackReason::UpstreamShape)?;
    if items.len() > MAX_ENTRIES_PER_PAGE {
        return Err(FallbackReason::UpstreamShape);
    }
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        entries.push(parse_entry(item)?);
    }
    Ok((true, entries))
}

/// Accept the documented single item as `data` or as `data.data`.
fn parse_detail_envelope(
    mime: Option<&str>,
    document: Option<&Value>,
) -> Result<(bool, Option<Entry>), FallbackReason> {
    if let Some(mime) = mime {
        if !json_mime(mime) {
            return Err(FallbackReason::UnexpectedContent);
        }
    }
    let document = document.ok_or(FallbackReason::UpstreamParse)?;
    let root = document.as_object().ok_or(FallbackReason::UpstreamShape)?;
    let success = match root.get("success") {
        Some(Value::Bool(value)) => *value,
        _ => return Err(FallbackReason::UpstreamShape),
    };
    if !success {
        return Ok((false, None));
    }
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or(FallbackReason::UpstreamShape)?;
    let item = match data.get("data") {
        Some(Value::Array(items)) if items.len() == 1 => &items[0],
        Some(Value::Array(items)) if items.is_empty() => return Ok((true, None)),
        Some(value @ Value::Object(_)) => value,
        None if data.contains_key("id") => root.get("data").ok_or(FallbackReason::UpstreamShape)?,
        _ => return Err(FallbackReason::UpstreamShape),
    };
    Ok((true, Some(parse_entry(item)?)))
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

fn reply_summary(reply: &Reply) -> Value {
    let preview: String = reply.content.chars().take(MAX_REPLY_PREVIEW_CHARS).collect();
    let truncated = preview.chars().count() < reply.content.chars().count();
    json!({
        "id": reply.id,
        "department": {"id": reply.department_id, "name": reply.department_name},
        "created_at": reply.created_at,
        "content_bytes": reply.content.len(),
        "content_sha256": sha256(reply.content.as_bytes()),
        "content_preview": preview,
        "content_truncated": truncated,
    })
}

fn entry_provenance(response: &Response) -> Value {
    json!({
        "source_url": response.url,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "response_body_sha256": response.sha256,
    })
}

fn project_entry(entry: &Entry, response: &Response) -> Value {
    let attachments: Vec<Value> = entry
        .attachments
        .iter()
        .map(|url| {
            json!({
                "url": url,
                "present": true,
                "existence_verified": false
            })
        })
        .collect();
    json!({
        "id": entry.id,
        "title": entry.title,
        "content": entry.content,
        "created_at": entry.created_at,
        "status": entry.status,
        "reply_count": entry.replies.len(),
        "replies": entry.replies.iter().map(reply_summary).collect::<Vec<Value>>(),
        "departments": entry.departments.iter().map(|(id, name)| json!({"id": id, "name": name})).collect::<Vec<Value>>(),
        "attachments": attachments,
        "provenance": entry_provenance(response),
    })
}

/// The degradation evidence: the original bytes when they are admissible, the
/// content type that was actually observed (`null` when the upstream sent
/// none, when the value carries the submitted credential, or when it is not a
/// well-formed MIME type), the byte length, the SHA-256 of the body and the
/// reason the structure could not be built.
fn evidence(reason: FallbackReason, response: &Response, token: &str) -> Value {
    let leading = response.body.trim_ascii_start();
    let json_source = response.headers.get("content-type").is_some_and(|mime|json_mime(mime))
        || leading.starts_with(b"{") || leading.starts_with(b"[") || leading.starts_with(b"\"");
    let credential_json = json_source && json_contains_credentials(&response.body,0);
    let credential_bearer = bearer_credential_present(&response.body);
    let credential_form = std::str::from_utf8(&response.body).ok().is_some_and(|source| {
        let document = scraper::Html::parse_document(source);
        let controls = scraper::Selector::parse("input,textarea,select,script").unwrap();
        if document.select(&controls).next().is_some() {
            return true;
        }
        // HTML metadata is document scope: a credential-marked meta is
        // credential-bearing wherever upstream placed it. The declared name
        // classifies it by the same key rules as JSON members; ordinary meta
        // names like description or viewport keep the raw body admissible.
        let metas = scraper::Selector::parse("meta").unwrap();
        document.select(&metas).any(|meta| {
            ["name", "http-equiv", "property", "itemprop"]
                .iter()
                .copied()
                .filter_map(|attr| meta.value().attr(attr))
                .any(credential_key)
        })
    });
    // A refusal body and a body that echoes the submitted token are never
    // exported, not even through the reversible base64 channel.
    let raw_safe = !credential_json
        && !credential_bearer
        && !credential_form
        && !matches!(
            reason,
            FallbackReason::SafetyLatched
                | FallbackReason::ChallengeUnreviewed
                | FallbackReason::AuthenticationRefused
                | FallbackReason::CredentialEcho
                | FallbackReason::InspectionUnreviewed
        );
    let mut value = json!({
        "fallback_reason": reason.code(),
        "content_type": content_type(response, token),
        "content_type_parameters_withheld": content_type_parameters_withheld(response, token),
        "byte_length": response.body.len(),
        "sha256": response.sha256,
        "evidence_kind": if raw_safe { "upstream_http_body" } else { "upstream_http_metadata" },
        "http_status": response.status,
    });
    if raw_safe {
        value["raw_response_base64"] = json!(STANDARD.encode(&response.body));
    }
    value
}

fn page_meta(response: &Response, entry_count: usize, token: &str) -> Value {
    json!({
        "url": response.url,
        "status": response.status,
        "content_type": content_type(response, token),
        "content_type_parameters_withheld": content_type_parameters_withheld(response, token),
        "entry_count": entry_count,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "response_body_sha256": response.sha256,
        "cache_status": response.cache_status,
    })
}

struct PageOutcome {
    meta: Value,
    success: Option<bool>,
    evidence: Option<Value>,
    entries: Vec<Value>,
}

fn cursor_is_incomparable(request: &ListRequest, entries: &[Entry]) -> bool {
    request.since_time.as_ref().is_some_and(|cursor| {
        entries.iter().any(|entry| {
            !request.known.contains_key(&entry.id)
                && request.since_id.is_none_or(|id| entry.id > id)
                && parse_timestamp(&entry.created_at)
                    .and_then(|created| compare_timestamps(&created, cursor))
                    .is_none()
        })
    })
}

fn page_is_terminal(outcome: &PageOutcome, limit: u32) -> bool {
    outcome.evidence.is_some()
        || outcome.success == Some(false)
        || outcome.entries.len() < limit as usize
}

fn advisory() -> Value {
    let hour = campus_local_hour(unix_seconds().unwrap_or(0));
    json!({
        "upstream_idle_window": "22:00-07:00 campus local time",
        "campus_local_hour": hour,
        "inside_idle_window": hour >= 22 || hour < 7,
        "enforced": false,
        "note": "advisory only; this adapter never blocks, delays or retries because of the idle window",
    })
}

fn attachments_notice() -> Value {
    json!({
        "downloaded": false,
        "contract": "unknown",
        "note": "the platform exposes no dedicated attachment endpoint; legacy php-ihome upload and attachment routes are reference-only, so no attachment endpoint is guessed and no declared URL is fetched",
    })
}

// ---------------------------------------------------------------------------
// Listing envelope
// ---------------------------------------------------------------------------

struct Counts {
    kept_new: usize,
    kept_changed: usize,
    skipped_unchanged: usize,
    skipped_at_or_before_since_id: usize,
    skipped_at_or_before_since_time: usize,
    uncomparable_created_at: usize,
}

/// Emit unseen records after the supplied cursor, or previously seen records
/// whose status or reply count has changed since the supplied baseline.
fn classify(
    request: &ListRequest,
    entry: &mut Value,
    counts: &mut Counts,
) -> Option<&'static str> {
    let (id, created_at, status, reply_count) = {
        let map = entry.as_object()?;
        (
            map.get("id").and_then(Value::as_u64)?,
            map.get("created_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            map.get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            map.get("reply_count")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        )
    };

    let change = match request.known.get(&id) {
        None => {
            if request.since_id.is_some_and(|since_id| id <= since_id) {
                counts.skipped_at_or_before_since_id += 1;
                return None;
            }
            if let Some(since_time) = request.since_time.as_ref() {
                match parse_timestamp(&created_at)
                    .and_then(|created| compare_timestamps(&created, since_time))
                {
                    Some(Ordering::Greater) => {}
                    Some(_) => {
                        counts.skipped_at_or_before_since_time += 1;
                        return None;
                    }
                    None => {
                        counts.uncomparable_created_at += 1;
                        return None;
                    }
                }
            }
            "new"
        }
        Some(previous) => {
            let status_changed = previous.status != status;
            let replies_changed = u64::from(previous.reply_count) != reply_count;
            match (status_changed, replies_changed) {
                (false, false) => {
                    counts.skipped_unchanged += 1;
                    return None;
                }
                (true, true) => "status_and_reply_count_changed",
                (true, false) => "status_changed",
                (false, true) => "reply_count_changed",
            }
        }
    };
    if change == "new" {
        counts.kept_new += 1;
    } else {
        counts.kept_changed += 1;
    }
    set_field(entry, "change", json!(change));
    set_field(entry, "created_at_comparable", json!(parse_timestamp(&created_at).is_some()));
    Some(change)
}

fn set_field(value: &mut Value, key: &str, field: Value) {
    if let Some(map) = value.as_object_mut() {
        map.insert(key.to_owned(), field);
    }
}

fn build_list_envelope(
    request: &ListRequest,
    pages: Vec<PageOutcome>,
    incomplete: Option<&'static str>,
) -> Value {
    let mut counts = Counts {
        kept_new: 0,
        kept_changed: 0,
        skipped_unchanged: 0,
        skipped_at_or_before_since_id: 0,
        skipped_at_or_before_since_time: 0,
        uncomparable_created_at: 0,
    };
    let mut entries: Vec<Value> = Vec::new();
    let mut max_id = request.since_id;
    let mut max_created_at = request.since_time_raw.clone();
    let mut incomparable_dates = false;
    let mut seen_ids = BTreeSet::new();
    let mut upstream_success: Option<bool> = None;
    let mut last_meta: Option<Value> = None;
    let mut page_records: Vec<Value> = Vec::new();
    let mut degraded_evidence: Option<Value> = None;

    for page in pages {
        page_records.push(page.meta.clone());
        last_meta = Some(page.meta.clone());
        if let Some(success) = page.success {
            upstream_success = Some(success);
        }
        if let Some(found) = page.evidence {
            degraded_evidence = Some(found);
            break;
        }
        for mut entry in page.entries {
            if let Some(map) = entry.as_object() {
                let id = map.get("id").and_then(Value::as_u64);
                let created_at = map.get("created_at").and_then(Value::as_str);
                if let Some(id) = id {
                    if !seen_ids.insert(id) {
                        continue;
                    }
                    max_id = Some(max_id.map_or(id, |current| current.max(id)));
                }
                if let Some(created_at) = created_at {
                    let replace = match parse_timestamp(created_at) {
                        Some(candidate) => match &max_created_at {
                            Some(current) => match parse_timestamp(current.as_str())
                                .and_then(|previous| compare_timestamps(&candidate, &previous)) {
                                Some(ordering) => ordering == Ordering::Greater,
                                None => { incomparable_dates = true; false },
                            },
                            None => true,
                        },
                        None => { incomparable_dates = true; false },
                    };
                    if replace {
                        max_created_at = Some(created_at.to_owned());
                    }
                }
            }
            if classify(request, &mut entry, &mut counts).is_some() {
                entries.push(entry);
            }
        }
    }

    if incomparable_dates {
        max_created_at = None;
    }
    let pages_fetched = page_records.len();
    let next_page = request.page.saturating_add(u32::try_from(pages_fetched).unwrap_or(0));
    let has_more = pages_fetched > 0
        && page_records
            .last()
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("entry_count"))
            .and_then(Value::as_u64)
            .is_some_and(|count| count == u64::from(request.limit));
    let complete = degraded_evidence.is_none() && !has_more;
    let provenance = match last_meta.as_ref().and_then(Value::as_object) {
        Some(meta) => json!({
            "source_url": meta.get("url").cloned().unwrap_or(Value::Null),
            "fetched_at_unix_ms": meta.get("fetched_at_unix_ms").cloned().unwrap_or(Value::Null),
            "response_body_sha256": meta.get("response_body_sha256").cloned().unwrap_or(Value::Null),
            "cache_status": meta.get("cache_status").cloned().unwrap_or(Value::Null),
        }),
        None => Value::Null,
    };

    let degraded = degraded_evidence.is_some();
    let incomplete_traversal = incomplete.is_some();
    let result = if degraded {
        "degraded"
    } else if incomplete_traversal {
        // The pages that were admitted stay published, but the traversal
        // itself did not finish.
        "partial"
    } else if entries.is_empty() {
        "empty"
    } else {
        "entries"
    };
    let entry_count = entries.len();
    // An incomplete traversal never advances the incremental cursor: the
    // unread page could still hold records below the admitted maximum.
    let next_cursor = if degraded || incomplete_traversal {
        Value::Null
    } else {
        json!({
            "max_id": max_id,
            "max_created_at": max_created_at,
            "next_page": if has_more { json!(next_page) } else { Value::Null },
            "has_more": has_more,
        })
    };
    json!({
        "schema_version": 1,
        "type": "ihome_appeal_list",
        "result": result,
        "upstream": {
            "success": upstream_success,
            "pages": page_records,
            "complete": complete && !incomplete_traversal,
            "incomplete": incomplete_traversal,
            "incomplete_reason": incomplete,
        },
        "entries": entries,
        "entry_count": entry_count,
        "next_cursor": next_cursor,
        "dedup": {
            "basis": "deduplicate by upstream id; emit unseen entries strictly after the supplied cursors, plus known entries whose status or reply count changed; preserve created_at verbatim",
            "since_id": request.since_id,
            "since_time": request.since_time_raw,
            "known_items": request.known.len(),
            "kept_new": counts.kept_new,
            "kept_changed": counts.kept_changed,
            "skipped_unchanged": counts.skipped_unchanged,
            "skipped_at_or_before_since_id": counts.skipped_at_or_before_since_id,
            "skipped_at_or_before_since_time": counts.skipped_at_or_before_since_time,
            "uncomparable_created_at": counts.uncomparable_created_at,
        },
        "credential_source": request.token_source.map(TokenSource::label),
        "attachments": attachments_notice(),
        "advisory": advisory(),
        "provenance": provenance,
        "upstream_evidence": degraded_evidence,
    })
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Unified CLI entry point.
///
/// The request JSON carries `"operation"`, either `"list"` or `"detail"`,
/// plus that operation's own fields. `online` permits one governed request
/// per page on a cache miss; nothing is retried.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid_input("the ihome request is too large"));
    }
    let selector: OperationSelector =
        serde_json::from_str(input).map_err(|_| invalid_input("the ihome request is invalid"))?;
    match selector.operation {
        Operation::List => list(input, online),
        Operation::Detail => detail(input, online),
    }
}

/// Read one bounded window of the appeal listing.
///
/// `online` permits one governed request per page on a cache miss. Nothing is
/// retried, and a rate limit or a refusal stops every further page.
pub fn list(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_list_input(input)?;
    if request.refresh && !online {
        return Err(invalid_input("refresh requires online authorization"));
    }
    let scope = sha256(request.token.as_bytes());
    let cache = ResponseCache::open(&scope)?;
    list_with_cache(&request, &cache, online)
}

/// The listing traversal over one credential-scoped cache.
fn list_with_cache(
    request: &ListRequest,
    cache: &ResponseCache,
    online: bool,
) -> Result<Value, Error> {
    let mut pages = Vec::new();
    let mut incomplete: Option<&'static str> = None;
    for offset in 0..request.max_pages {
        let page = request.page.saturating_add(offset);
        let url = list_url(request.limit, page)?;
        let outcome = match cache.get(
            &url,
            request.token.as_str(),
            online,
            request.refresh,
            |response, challenge, facts| {
                Ok::<PageOutcome, Error>(list_page(request, response, challenge, facts))
            },
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if pages.is_empty() {
                    // Nothing was admitted yet, so the refusal itself is the
                    // only truthful outcome.
                    return Err(error);
                }
                // A later page could not be fetched. The pages that were
                // already admitted stay valid; the traversal is reported as
                // incomplete, the reason is named, and the incremental cursor
                // is not advanced.
                incomplete = Some(error.code);
                break;
            }
        };
        let stop = page_is_terminal(&outcome, request.limit);
        pages.push(outcome);
        if stop {
            break;
        }
    }
    Ok(build_list_envelope(request, pages, incomplete))
}

/// Structure one listing page. A refusal, an echoed token and an explicit
/// session denial are never presented as an empty listing.
fn list_page(
    request: &ListRequest,
    response: &Response,
    challenge: &ChallengeAssessment,
    facts: &ResponseFacts,
) -> PageOutcome {
    if facts.token_echo {
        // The upstream echoed the submitted bearer token. Nothing from this
        // body is projected or exported, not even as the raw evidence of
        // another refusal.
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: None,
            evidence: Some(evidence(FallbackReason::CredentialEcho, response, request.token.as_str())),
            entries: Vec::new(),
        };
    }
    if facts.inspection_incomplete {
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()), success: None,
            evidence: Some(evidence(FallbackReason::InspectionUnreviewed, response, request.token.as_str())), entries: Vec::new(),
        };
    }
    if let Some(reason) = response_refusal(response, challenge) {
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: None,
            evidence: Some(evidence(reason, response, request.token.as_str())),
            entries: Vec::new(),
        };
    }
    if facts.session_denied {
        // An explicit session denial is not an empty listing.
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: Some(false),
            evidence: Some(evidence(FallbackReason::AuthenticationRefused, response, request.token.as_str())),
            entries: Vec::new(),
        };
    }
    let mime = response.headers.get("content-type").map(String::as_str);
    match parse_envelope(mime, facts.document.as_ref()) {
        Ok((true, entries)) if entries.len() > request.limit as usize => PageOutcome {
            meta: page_meta(response, entries.len(), request.token.as_str()),
            success: Some(true),
            evidence: Some(evidence(FallbackReason::UpstreamShape, response, request.token.as_str())),
            entries: Vec::new(),
        },
        Ok((true, entries)) if cursor_is_incomparable(request, &entries) => PageOutcome {
            meta: page_meta(response, entries.len(), request.token.as_str()),
            success: Some(true),
            evidence: Some(evidence(FallbackReason::IncomparableTimestamp, response, request.token.as_str())),
            entries: Vec::new(),
        },
        Ok((success, entries)) => PageOutcome {
            meta: page_meta(response, entries.len(), request.token.as_str()),
            success: Some(success),
            evidence: None,
            entries: entries
                .iter()
                .map(|entry| project_entry(entry, response))
                .collect(),
        },
        Err(reason) => PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: None,
            evidence: Some(evidence(reason, response, request.token.as_str())),
            entries: Vec::new(),
        },
    }
}

/// Read one appeal by its upstream id.
pub fn detail(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_detail_input(input)?;
    if request.refresh && !online {
        return Err(invalid_input("refresh requires online authorization"));
    }
    let scope = sha256(request.token.as_bytes());
    let cache = ResponseCache::open(&scope)?;
    let url = detail_url(request.id)?;
    let outcome = cache.get(
        &url,
        request.token.as_str(),
        online,
        request.refresh,
        |response, challenge, facts| {
            Ok::<PageOutcome, Error>(detail_page(&request, response, challenge, facts))
        },
    )?;
    let degraded = outcome.evidence.is_some();
    let entry = outcome.entries.into_iter().next();
    let result = if degraded {
        "degraded"
    } else if entry.is_some() {
        "appeal"
    } else {
        "not_found"
    };
    let provenance = match outcome.meta.as_object() {
        Some(meta) => json!({
            "source_url": meta.get("url").cloned().unwrap_or(Value::Null),
            "fetched_at_unix_ms": meta.get("fetched_at_unix_ms").cloned().unwrap_or(Value::Null),
            "response_body_sha256": meta.get("response_body_sha256").cloned().unwrap_or(Value::Null),
            "cache_status": meta.get("cache_status").cloned().unwrap_or(Value::Null),
        }),
        None => Value::Null,
    };
    Ok(json!({
        "schema_version": 1,
        "type": "ihome_appeal_detail",
        "result": result,
        "upstream": {"success": outcome.success, "id": request.id},
        "entry": entry,
        "credential_source": request.token_source.map(TokenSource::label),
        "attachments": attachments_notice(),
        "advisory": advisory(),
        "provenance": provenance,
        "upstream_evidence": outcome.evidence,
    }))
}

/// Structure one appeal. A refusal, an echoed token and an explicit session
/// denial are never presented as a missing appeal.
fn detail_page(
    request: &DetailRequest,
    response: &Response,
    challenge: &ChallengeAssessment,
    facts: &ResponseFacts,
) -> PageOutcome {
    if facts.token_echo {
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: None,
            evidence: Some(evidence(FallbackReason::CredentialEcho, response, request.token.as_str())),
            entries: Vec::new(),
        };
    }
    if facts.inspection_incomplete {
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()), success: None,
            evidence: Some(evidence(FallbackReason::InspectionUnreviewed, response, request.token.as_str())), entries: Vec::new(),
        };
    }
    if let Some(reason) = response_refusal(response, challenge) {
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: None,
            evidence: Some(evidence(reason, response, request.token.as_str())),
            entries: Vec::new(),
        };
    }
    if facts.session_denied {
        return PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: Some(false),
            evidence: Some(evidence(FallbackReason::AuthenticationRefused, response, request.token.as_str())),
            entries: Vec::new(),
        };
    }
    let mime = response.headers.get("content-type").map(String::as_str);
    match parse_detail_envelope(mime, facts.document.as_ref()) {
        Ok((true, Some(entry))) if entry.id != request.id => PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: Some(true),
            evidence: Some(evidence(FallbackReason::UpstreamShape, response, request.token.as_str())),
            entries: Vec::new(),
        },
        Ok((success, entry)) => PageOutcome {
            meta: page_meta(response, usize::from(entry.is_some()), request.token.as_str()),
            success: Some(success),
            evidence: None,
            entries: entry
                .map(|entry| vec![project_entry(&entry, response)])
                .unwrap_or_default(),
        },
        Err(reason) => PageOutcome {
            meta: page_meta(response, 0, request.token.as_str()),
            success: None,
            evidence: Some(evidence(reason, response, request.token.as_str())),
            entries: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

fn token_schema() -> Value {
    json!({
        "type": ["string", "null"],
        "minLength": 1,
        "maxLength": MAX_TOKEN_BYTES,
        "pattern": "^[!-~]+$",
        "description": "The ihome bearer token produced by the session layer from the SSO redirect chain (?token= or #token=) or from the appeal_pc_token cookie. It is read from stdin only, is never persisted, logged, echoed, or written to any file, and this module never logs in. A missing or null token is accepted by the parser and then refused with authorization_required before any cache or network access. Credential-echo inspection is conservative: an accidental substring or supported encoded-form match in an upstream body is also withheld, which is more likely with short tokens.",
    })
}

fn entry_schema(include_change: bool) -> Value {
    let mut required = vec![
        "id",
        "title",
        "content",
        "created_at",
        "status",
        "reply_count",
        "replies",
        "departments",
        "attachments",
        "provenance",
    ];
    let mut properties = json!({
        "id": {"type": "integer", "minimum": 0},
        "title": {"type": "string"},
        "content": {"type": "string"},
        "created_at": {"type": "string", "description": "The canonical upstream created_at value, copied verbatim and never re-derived."},
        "status": {"type": "string", "description": "The upstream publish_status_text value."},
        "reply_count": {"type": "integer", "minimum": 0},
        "replies": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id","department","created_at","content_bytes","content_sha256","content_preview","content_truncated"],
                "properties": {
                    "id": {"type": "integer", "minimum": 0},
                    "department": {"type": "object", "additionalProperties": false, "required": ["id","name"], "properties": {"id": {"type": "integer", "minimum": 0}, "name": {"type": "string"}}},
                    "created_at": {"type": "string", "description": "The canonical upstream reply created_at value, copied verbatim."},
                    "content_bytes": {"type": "integer", "minimum": 0},
                    "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "content_preview": {"type": "string"},
                    "content_truncated": {"type": "boolean"}
                }
            }
        },
        "departments": {
            "type": "array",
            "items": {"type": "object", "additionalProperties": false, "required": ["id","name"], "properties": {"id": {"type": "integer", "minimum": 0}, "name": {"type": "string"}}}
        },
        "attachments": {
            "type": "array",
            "description": "URLs that the upstream record itself declares, with their presence. No attachment is downloaded, no attachment endpoint is guessed, and remote existence is not verified.",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["url","present","existence_verified"],
                "properties": {
                    "url": {"type": "string"},
                    "present": {"const": true},
                    "existence_verified": {"const": false}
                }
            }
        },
        "provenance": entry_provenance_schema()
    });
    if include_change {
        required.push("change");
        required.push("created_at_comparable");
        if let Some(map) = properties.as_object_mut() {
            map.insert(
                "change".to_owned(),
                json!({"enum": ["new","status_changed","reply_count_changed","status_and_reply_count_changed"]}),
            );
            map.insert(
                "created_at_comparable".to_owned(),
                json!({"type": "boolean", "description": "False when the upstream timestamp could not be parsed, so an ordering decision was not possible."}),
            );
        }
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

fn entry_provenance_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["source_url","fetched_at_unix_ms","response_body_sha256"],
        "properties": {
            "source_url": {"type": "string"},
            "fetched_at_unix_ms": {"type": "integer", "minimum": 0},
            "response_body_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
}

fn response_provenance_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": ["source_url","fetched_at_unix_ms","response_body_sha256","cache_status"],
        "properties": {
            "source_url": {"type": ["string", "null"]},
            "fetched_at_unix_ms": {"type": ["integer", "null"], "minimum": 0},
            "response_body_sha256": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"},
            "cache_status": {"enum": ["hit", "miss", "revalidated", null]}
        }
    })
}

fn page_meta_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["url","status","content_type","content_type_parameters_withheld","entry_count","fetched_at_unix_ms","response_body_sha256","cache_status"],
        "properties": {
            "url": {"type": "string"},
            "status": {"type": "integer", "minimum": 100, "maximum": 999},
            "content_type": {"type": ["string", "null"]},
            "content_type_parameters_withheld": {"type":"boolean", "description": "True when the response declared a content type that is not fully projected: untrusted parameters, a malformed value, or a value carrying the submitted credential."},
            "entry_count": {"type": "integer", "minimum": 0},
            "fetched_at_unix_ms": {"type": "integer", "minimum": 0},
            "response_body_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "cache_status": {"enum": ["hit", "miss", "revalidated"]}
        }
    })
}

fn attachments_notice_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["downloaded","contract","note"],
        "properties": {
            "downloaded": {"const": false},
            "contract": {"const": "unknown"},
            "note": {"type": "string"}
        }
    })
}

fn evidence_schema() -> Value {
    json!({
        "type": ["object", "null"],
        "description": "Degraded evidence with observed content type, byte length, SHA-256 and status. Safe source bytes are included; safety-latched and unreviewed challenge bodies are withheld even on offline cache reads. Original bytes remain in the private credential-scoped cache.",
        "additionalProperties": false,
        "required": ["fallback_reason","content_type","content_type_parameters_withheld","byte_length","sha256","evidence_kind","http_status"],
        "properties": {
            "fallback_reason": {"enum": ["unexpected_content","upstream_parse","upstream_shape","rate_limited","safety_latched","challenge_unreviewed","redirect_refused","http_rejected","unsupported_encoding","incomparable_timestamp","authentication_refused","credential_echo","inspection_unreviewed"]},
            "content_type": {"type": ["string", "null"], "description": "Safe observed MIME essence; null when absent or unsafe. Untrusted parameters are withheld, never replaced by an expected MIME."},
            "content_type_parameters_withheld": {"type":"boolean", "description": "True when the response declared a content type that is not fully projected: untrusted parameters, a malformed value, or a value carrying the submitted credential."},
            "byte_length": {"type": "integer", "minimum": 0},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "raw_response_base64": {"type": "string", "contentEncoding": "base64"},
            "evidence_kind": {"enum": ["upstream_http_body", "upstream_http_metadata"]},
            "http_status": {"type": "integer", "minimum": 100, "maximum": 999}
        }
    })
}

fn advisory_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["upstream_idle_window","campus_local_hour","inside_idle_window","enforced","note"],
        "properties": {
            "upstream_idle_window": {"type": "string"},
            "campus_local_hour": {"type": "integer", "minimum": 0, "maximum": 23},
            "inside_idle_window": {"type": "boolean"},
            "enforced": {"const": false},
            "note": {"type": "string"}
        }
    })
}

fn token_source_schema() -> Value {
    json!({
        "enum": ["redirect_query_token","redirect_fragment_token","cookie_appeal_pc_token", null],
        "description": "Optional declaration of where the bearer token came from. It is recorded in the output as credential_source; the token value itself is never emitted."
    })
}

fn list_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [],
        "properties": {
            "token": token_schema(),
            "operation": {"enum": ["list", null], "description": "Optional for direct list calls; required and non-null by run."},
            "token_source": token_source_schema(),
            "limit": {"type": ["integer", "null"], "minimum": 1, "maximum": MAX_LIMIT, "default": DEFAULT_LIMIT, "description": "Absent or null selects the default."},
            "page": {"type": ["integer", "null"], "minimum": 1, "maximum": MAX_PAGE, "default": 1, "description": "Absent or null selects page 1."},
            "max_pages": {"type": ["integer", "null"], "minimum": 1, "maximum": MAX_PAGES, "default": DEFAULT_PAGES, "description": "Explicit bound for consecutive pages; absent or null means one. Each page owns its own lease."},
            "since_id": {"type": ["integer", "null"], "minimum": 0, "maximum": u64::MAX, "description": "Exclusive lower bound for unseen entries. Known entries are emitted if their status or reply count changed, even if older than the cursor."},
            "since_time": {"type": ["string", "null"], "description": "Exclusive cursor: RFC3339 with an offset, or a floating YYYY-MM-DD HH:MM:SS timestamp. Floating values compare only to floating source dates; offset values only to offset source dates. Incomparable dates cause degraded evidence, not a guessed timezone."},
            "known": {
                "type": ["array", "null"],
                "maxItems": MAX_KNOWN_ITEMS,
                "description": "Optional persisted set of already observed records used for change detection. An entry whose status and reply count are unchanged is skipped; a changed status or reply count keeps it and marks it changed. The caller rebuilds this set from the status and reply_count of the previous entries, or persists only next_cursor.max_id.",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id","status","reply_count"],
                    "properties": {
                        "id": {"type": "integer", "minimum": 0},
                        "status": {"type": "string"},
                        "reply_count": {"type": "integer", "minimum": 0, "maximum": u32::MAX}
                    }
                }
            },
            "refresh": {"type": ["boolean", "null"], "default": false, "description": "Explicitly fetch fresh data, bypassing the cache; requires --online. Absent or null is false."},
            "download_attachments": {"type": ["boolean", "null"], "default": false, "description": "true is refused with unsupported: attachment download is not implemented, the platform exposes no dedicated attachment endpoint, and the legacy attachment contract is unknown."}
        }
    })
}

fn detail_input_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id"],
        "properties": {
            "token": token_schema(),
            "operation": {"enum": ["detail", null], "description": "Optional for direct detail calls; required and non-null by run."},
            "token_source": token_source_schema(),
            "id": {"type": "integer", "minimum": 0, "maximum": u64::MAX, "description": "The upstream appeal id."},
            "refresh": {"type": ["boolean", "null"], "default": false, "description": "Explicitly fetch fresh data, bypassing the cache; requires --online. Absent or null is false."},
            "download_attachments": {"type": ["boolean", "null"], "default": false, "description": "true is refused with unsupported: attachment download is not implemented and the upstream attachment contract is unknown."}
        }
    })
}

/// Build the `run` variant of one operation's input schema by adding the
/// operation discriminator to that operation's own member set.
fn run_input_schema(operation: &str, base: Value) -> Value {
    let mut schema = base;
    if let Some(map) = schema.as_object_mut() {
        let mut required = vec![json!("operation")];
        if let Some(Value::Array(existing)) = map.get("required") {
            for member in existing {
                required.push((*member).clone());
            }
        }
        map.insert("required".to_owned(), Value::Array(required));
        if let Some(properties) = map.get_mut("properties").and_then(Value::as_object_mut) {
            properties.insert(
                "operation".to_owned(),
                json!({"const": operation, "description": "Selects this upstream read."}),
            );
        }
    }
    schema
}

/// Machine-readable stdin/output contracts for CLI integration.
pub fn schema() -> Value {
    let mut contract = json!({
        "$defs": {
            "entry_provenance": entry_provenance_schema(),
            "entry": entry_schema(false),
            "list_entry": entry_schema(true),
            "list_input": list_input_schema(),
            "detail_input": detail_input_schema(),
            "run_list_input": run_input_schema("list", list_input_schema()),
            "run_detail_input": run_input_schema("detail", detail_input_schema())
        },
        "run": {
            "input": {
                "type": "object",
                "description": "The unified CLI entry point. The operation selects the upstream read; the remaining members are that operation's own fields. Every operation requires an explicit bearer token from the session layer, and login is never performed here.",
                "oneOf": [
                    run_input_schema("list", list_input_schema()),
                    run_input_schema("detail", detail_input_schema())
                ]
            },
            "options": {
                "--online": "Permit one governed request per page on a cache miss; refresh:true explicitly bypasses cached pages. No automatic retry."
            },
            "output": {
                "description": "Operation-specific output."
            }
        },
        "list": {
            "input": list_input_schema(),
            "options": {
                "--online": "Permit one governed request per page on a cache miss; refresh:true explicitly bypasses cached pages. No automatic retry."
            },
            "output": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schema_version","type","result","upstream","entries","entry_count","next_cursor","dedup","credential_source","attachments","advisory","provenance","upstream_evidence"],
                "properties": {
                    "schema_version": {"const": 1},
                    "type": {"const": "ihome_appeal_list"},
                    "result": {"enum": ["entries","empty","partial","degraded"], "description": "empty covers an upstream success=false business answer and a page with no entries; partial means a later page could not be fetched and the pages already admitted remain published; degraded means the response was refused or could not be structured and upstream_evidence carries the reason and the original bytes when they are admissible."},
                    "upstream": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["success","pages","complete","incomplete","incomplete_reason"],
                        "properties": {
                            "success": {"type": ["boolean","null"], "description": "The upstream success flag; false with no upstream_evidence is an empty listing, not an error. An explicit session denial also reports false and carries upstream_evidence with fallback_reason authentication_refused."},
                            "pages": {"type": "array", "items": page_meta_schema()},
                            "complete": {"type": "boolean", "description": "True only when the whole requested window was fetched and structured."},
                            "incomplete": {"type": "boolean", "description": "True when a later page could not be fetched. The pages already admitted remain valid and are published."},
                            "incomplete_reason": {"type": ["string","null"], "description": "The refusal code of the page that could not be fetched, or null when the traversal finished."}
                        }
                    },
                    "entries": {"type": "array", "items": entry_schema(true)},
                    "entry_count": {"type": "integer", "minimum": 0},
                    "next_cursor": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "required": ["max_id","max_created_at","next_page","has_more"],
                        "properties": {
                            "max_id": {"type": ["integer", "null"], "minimum": 0, "description": "Highest id observed in this window. Aggregate the maximum across pages and advance since_id only after completing the page traversal."},
                            "max_created_at": {"type": ["string", "null"], "description": "Newest comparable upstream created_at, copied verbatim; null if timestamps are incomparable or unavailable."},
                            "next_page": {"type": ["integer", "null"], "minimum": 1},
                            "has_more": {"type": "boolean"}
                        }
                    },
                    "dedup": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["basis","since_id","since_time","known_items","kept_new","kept_changed","skipped_unchanged","skipped_at_or_before_since_id","skipped_at_or_before_since_time","uncomparable_created_at"],
                        "properties": {
                            "basis": {"type": "string"},
                            "since_id": {"type": ["integer", "null"], "minimum": 0},
                            "since_time": {"type": ["string", "null"]},
                            "known_items": {"type": "integer", "minimum": 0},
                            "kept_new": {"type": "integer", "minimum": 0},
                            "kept_changed": {"type": "integer", "minimum": 0},
                            "skipped_unchanged": {"type": "integer", "minimum": 0},
                            "skipped_at_or_before_since_id": {"type": "integer", "minimum": 0},
                            "skipped_at_or_before_since_time": {"type": "integer", "minimum": 0},
                            "uncomparable_created_at": {"type": "integer", "minimum": 0, "description": "Incomparable dates cause degraded evidence rather than a fabricated cursor decision."}
                        }
                    },
                    "credential_source": {"type": ["string", "null"], "enum": ["redirect_query_token","redirect_fragment_token","cookie_appeal_pc_token", null]},
                    "attachments": attachments_notice_schema(),
                    "advisory": advisory_schema(),
                    "provenance": response_provenance_schema(),
                    "upstream_evidence": evidence_schema()
                }
            }
        },
        "detail": {
            "input": detail_input_schema(),
            "options": {
                "--online": "Permit one governed request on a cache miss. There is no automatic retry."
            },
            "output": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schema_version","type","result","upstream","entry","credential_source","attachments","advisory","provenance","upstream_evidence"],
                "properties": {
                    "schema_version": {"const": 1},
                    "type": {"const": "ihome_appeal_detail"},
                    "result": {"enum": ["appeal","not_found","degraded"]},
                    "upstream": {"type": "object", "additionalProperties": false, "required": ["success","id"], "properties": {"success": {"type": ["boolean", "null"]}, "id": {"type": "integer", "minimum": 0}}},
                    "entry": {"anyOf": [entry_schema(false), {"type": "null"}]},
                    "credential_source": {"type": ["string", "null"], "enum": ["redirect_query_token","redirect_fragment_token","cookie_appeal_pc_token", null]},
                    "attachments": attachments_notice_schema(),
                    "advisory": advisory_schema(),
                    "provenance": response_provenance_schema(),
                    "upstream_evidence": evidence_schema()
                }
            }
        },
        "unknown": {
            "attachment_download": "The modern platform has no dedicated attachment endpoint. The legacy php-ihome routes (POST /cp.php?ac=upload&type=attach with the multipart field attachupload, GET /attachment/<path>) are reference-only and their request and response contract is UNKNOWN, so no attachment endpoint is implemented or guessed here. Attachment extraction is limited to declared absolute URLs and structured values in body_data and image fields; unrecognized source layouts and remote URL existence are unverified.",
            "webvpn": "WebVPN URL encryption is an upstream client-side detail. It is documented here and deliberately not implemented; only direct HTTPS to i.buaa.edu.cn is used.",
            "idle_window": "The upstream 22:00-07:00 idle protection is surfaced as an advisory hint only and is never enforced by this adapter.",
            "login": "Login is not implemented here. The session layer supplies the bearer token; a missing token is refused as authorization_required.",
            "online_acceptance": "This adapter has not been exercised against the live campus service; its online acceptance is still unverified."
        }
    });
    let list_output = contract["list"]["output"].clone();
    let detail_output = contract["detail"]["output"].clone();
    contract["run"]["output"] = json!({"oneOf": [list_output, detail_output]});
    contract
}

#[cfg(test)]
mod rawvalue_regressions {
    use super::*;

    fn response(body: &[u8]) -> Response {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        Response {
            url: "https://i.buaa.edu.cn/api/appeal?limit=20&page=1".to_owned(),
            status: 200,
            headers,
            body: body.to_vec(),
            sha256: sha256(body),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    fn pages(body: &[u8], token: &str) -> (ResponseFacts, PageOutcome, PageOutcome) {
        let response = response(body);
        let facts = analyze_body(body, token);
        let list = ListRequest {
            token: Zeroizing::new(token.to_owned()), token_source: None,
            limit: 20, page: 1, max_pages: 1, since_id: None,
            since_time_raw: None, since_time: None, known: BTreeMap::new(), refresh: false,
        };
        let detail = DetailRequest {
            token: Zeroizing::new(token.to_owned()), token_source: None, id: 41, refresh: false,
        };
        let listing = list_page(&list, &response, &ChallengeAssessment::Clear, &facts);
        let detail = detail_page(&detail, &response, &ChallengeAssessment::Clear, &facts);
        (facts, listing, detail)
    }

    fn assert_refusal(page: &PageOutcome, reason: &str) {
        assert!(page.entries.is_empty());
        let evidence = page.evidence.as_ref().expect("refusal evidence");
        assert!(evidence.get("raw_response_base64").is_none(), "reversible raw response leaked");
        assert_eq!(evidence["evidence_kind"], "upstream_http_metadata");
        assert_eq!(evidence["fallback_reason"], reason);
    }

    #[test]
    fn short_echo() {
        let body = br#"{"$serde_json::private::RawValue":"","echo":"abc_123"}"#;
        let (facts, listing, detail) = pages(body, "abc_123");
        assert_refusal(&listing, "credential_echo");
        assert_refusal(&detail, "credential_echo");
        assert!(facts.token_echo);
        assert!(!facts.session_denied);
    }

    #[test]
    fn echo_and_denial() {
        let body = br#"{"$serde_json::private::RawValue":"","success":false,"message":"unauthorized","echo":"abc_123"}"#;
        let (facts, listing, detail) = pages(body, "abc_123");
        assert!(facts.session_denied, "explicit denial must survive the marker");
        assert!(facts.token_echo, "short exact token must be detected");
        // Credential privacy takes precedence in projection, while the denial
        // fact remains available independently for governor settlement.
        assert_refusal(&listing, "credential_echo");
        assert_refusal(&detail, "credential_echo");
    }

    #[test]
    fn denial() {
        let body = br#"{"$serde_json::private::RawValue":"","success":false,"message":"unauthorized"}"#;
        let (facts, listing, detail) = pages(body, "abc_123");
        assert!(facts.session_denied);
        assert!(!facts.token_echo);
        for page in [&listing, &detail] {
            assert_refusal(page, "authentication_refused");
            assert_eq!(page.success, Some(false));
        }
    }

    #[test]
    fn controls() {
        let (facts, listing, detail) = pages(br#"{"success":false,"message":"ordinary"}"#, "abc_123");
        assert!(!facts.token_echo && !facts.session_denied);
        for page in [&listing, &detail] {
            assert_eq!(page.success, Some(false));
            assert!(page.evidence.is_none());
        }

        for (body, token) in [
            (br#"{"message":"abc_123"}"#.as_slice(), "abc_123"),
            (br#"{"message":"prefix abc_1234 suffix"}"#.as_slice(), "abc_1234"),
        ] {
            let (facts, listing, detail) = pages(body, token);
            assert!(facts.token_echo);
            assert_refusal(&listing, "credential_echo");
            assert_refusal(&detail, "credential_echo");
        }
        // The marker is an ordinary member, not an encoded replacement root.
        let body = br#"{"$serde_json::private::RawValue":"{\"success\":false,\"message\":\"unauthorized\"}","success":true,"data":{"data":[]}}"#;
        let (facts, listing, _) = pages(body, "abc_123");
        assert!(!facts.session_denied && !facts.token_echo);
        assert_eq!(listing.success, Some(true));
        let (facts, listing, _) = pages(br#"{"$serde_json::private::RawValue":"ordinary"}"#, "abc_123");
        assert!(!facts.token_echo && !facts.session_denied);
        let fallback = listing.evidence.as_ref().unwrap();
        assert_eq!(fallback["evidence_kind"], "upstream_http_body");
        assert!(fallback.get("raw_response_base64").is_some());
        let (facts, _, _) = pages(br#"{"$serde_json::private::RawValue":"1234567"}"#, "1234567");
        assert!(facts.token_echo);
        let (facts, _, _) = pages(br#"{"echo":"abc_123","echo":"safe","success":false,"message":"unauthorized","success":true}"#, "abc_123");
        assert!(facts.token_echo && !facts.session_denied);
        let (facts, _, _) = pages(br#"{"nested":"{\"$serde_json::private::RawValue\":\"\\u0061bc_123\"}"}"#, "abc_123");
        assert!(facts.token_echo);

        let (facts, _, _) = pages(br#"{"value":"\ud83d\ude00"}"#, "😀");
        assert!(facts.token_echo);
        let (facts, _, _) = pages(br#"{"value":"YWJj"}"#, "abc");
        assert!(facts.token_echo);

        let mut urls = Vec::new();
        collect_declared_urls(&Value::String(r#"{"$serde_json::private::RawValue":"\"https://example.invalid/file\""}"#.to_owned()), &mut urls, 0);
        assert!(urls.is_empty());
        collect_declared_urls(&Value::String(r#"{"url":"https://example.invalid/file"}"#.to_owned()), &mut urls, 0);
        assert_eq!(urls, ["https://example.invalid/file"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn response(url: &Url, body: &[u8], content_type: Option<&str>) -> Response {
        let mut headers = BTreeMap::new();
        if let Some(value) = content_type {
            headers.insert("content-type".to_owned(), value.to_owned());
        }
        Response {
            url: url.as_str().to_owned(),
            status: 200,
            headers,
            body: body.to_vec(),
            sha256: sha256(body),
            fetched_at_unix_ms: 1_700_000_000_000,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    const LIST_BODY: &[u8] = br#"{
        "success": true,
        "data": {
            "data": [
                {
                    "id": 41,
                    "title": "Dormitory heating",
                    "content": "The dormitory heating is not working.",
                    "created_at": "2026-10-20 08:30:00",
                    "publish_status_text": "Replied",
                    "user": {"id": 7, "username": "student", "email": "s@example.edu", "pivot": {"user": 7}},
                    "departments": [{"id": 3, "name": "Logistics"}],
                    "appeal_reply": [
                        {"id": 900, "department": {"id": 3, "name": "Logistics"}, "content": "Please contact the office.", "created_at": "2026-10-21 09:00:00"}
                    ],
                    "campus": "Shahe",
                    "follow_count": 2,
                    "praise_count": 5,
                    "hot": 0,
                    "sqlb": {"type_name": "Daily life"},
                    "body_data": "https://i.buaa.edu.cn/storage/2026/10/photo.jpg",
                    "image_1": "/storage/2026/10/a.jpg",
                    "image_1_link": "https://cdn.i.buaa.edu.cn/storage/2026/10/a.jpg"
                },
                {
                    "id": 42,
                    "title": "Library seat",
                    "content": "Please extend the borrowing period.",
                    "created_at": "2026-10-22 10:15:00",
                    "publish_status_text": "Pending",
                    "departments": [],
                    "appeal_reply": [],
                    "campus": "Shahe",
                    "follow_count": 0,
                    "praise_count": 0,
                    "hot": 0,
                    "sqlb": {"type_name": "Study"}
                }
            ]
        }
    }"#;

    fn list_request(limit: u32) -> ListRequest {
        ListRequest {
            token: Zeroizing::new("synthetic-token".to_owned()),
            token_source: Some(TokenSource::RedirectQueryToken),
            limit,
            page: 1,
            max_pages: 1,
            since_id: None,
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::new(),
            refresh: false,
        }
    }

    fn page_from(body: &[u8], mime: Option<&str>) -> PageOutcome {
        let url = list_url(20, 1).unwrap();
        let original = response(&url, body, mime);
        let observed = content_type(&original, "synthetic-token-value");
        let facts = analyze_body(&original.body, "synthetic-token-value");
        match parse_envelope(observed.as_deref(), facts.document.as_ref()) {
            Ok((success, entries)) => PageOutcome {
                meta: page_meta(&original, entries.len(), "synthetic-token-value"),
                success: Some(success),
                evidence: None,
                entries: entries
                    .iter()
                    .map(|entry| project_entry(entry, &original))
                    .collect(),
            },
            Err(reason) => PageOutcome {
                meta: page_meta(&original, 0, "synthetic-token-value"),
                success: None,
                evidence: Some(evidence(reason, &original, "synthetic-token-value")),
                entries: Vec::new(),
            },
        }
    }

    #[test]
    fn listing_is_normalized_with_declared_attachments_only() {
        let request = list_request(20);
        let envelope =
            build_list_envelope(&request, vec![page_from(LIST_BODY, Some("application/json"))], None);
        assert_eq!(envelope["result"], "entries");
        assert_eq!(envelope["entry_count"], 2);
        let first = &envelope["entries"][0];
        assert_eq!(first["id"], 41);
        assert_eq!(first["title"], "Dormitory heating");
        assert_eq!(first["created_at"], "2026-10-20 08:30:00");
        assert_eq!(first["status"], "Replied");
        assert_eq!(first["reply_count"], 1);
        assert_eq!(first["replies"][0]["created_at"], "2026-10-21 09:00:00");
        assert_eq!(first["replies"][0]["department"]["name"], "Logistics");
        assert_eq!(first["departments"][0]["id"], 3);
        assert_eq!(first["change"], "new");
        assert_eq!(first["created_at_comparable"], true);
        let urls: Vec<&str> = first["attachments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["url"].as_str().unwrap())
            .collect();
        assert_eq!(
            urls,
            vec![
                "https://i.buaa.edu.cn/storage/2026/10/photo.jpg",
                "https://cdn.i.buaa.edu.cn/storage/2026/10/a.jpg"
            ]
        );
        assert!(urls.iter().all(|url| !url.starts_with('/')));
        assert_eq!(first["attachments"][0]["present"], true);
        assert_eq!(first["attachments"][0]["existence_verified"], false);
        assert_eq!(
            first["provenance"]["source_url"],
            "https://i.buaa.edu.cn/api/appeal?limit=20&page=1"
        );
        assert_eq!(envelope["upstream_evidence"], Value::Null);
        assert_eq!(envelope["attachments"]["downloaded"], false);
        assert_eq!(envelope["attachments"]["contract"], "unknown");
        assert_eq!(envelope["credential_source"], "redirect_query_token");
    }

    #[test]
    fn detail_parses_one_record_and_keeps_the_canonical_dates() {
        let url = detail_url(41).unwrap();
        let body = br#"{"success":true,"data":{"data":{"id":41,"title":"Dormitory heating","content":"Body","created_at":"2026-10-20 08:30:00","publish_status_text":"Replied","departments":[{"id":3,"name":"Logistics"}],"appeal_reply":[{"id":900,"department":{"id":3,"name":"Logistics"},"content":"Reply","created_at":"2026-10-21 09:00:00"}]}}}"#;
        let original = response(&url, body, Some("application/json"));
        let observed = content_type(&original, "synthetic-token-value");
        let facts = analyze_body(&original.body, "synthetic-token-value");
        let (success, entry) =
            parse_detail_envelope(observed.as_deref(), facts.document.as_ref()).unwrap();
        assert!(success);
        let entry = entry.unwrap();
        assert_eq!(entry.id, 41);
        assert_eq!(entry.created_at, "2026-10-20 08:30:00");
        assert_eq!(entry.replies[0].created_at, "2026-10-21 09:00:00");
        assert_eq!(entry.status, "Replied");

        let direct = br#"{"success":true,"data":{"id":41,"title":"t","content":"c","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}}"#;
        let direct_facts = analyze_body(direct, "synthetic-token-value");
        assert_eq!(
            parse_detail_envelope(Some("application/json"), direct_facts.document.as_ref())
                .unwrap()
                .1
                .unwrap()
                .id,
            41
        );
    }

    #[test]
    fn upstream_success_false_is_an_empty_listing_not_an_error() {
        let body = br#"{"success":false,"data":{"data":[]}}"#;
        let page = page_from(body, Some("application/json"));
        assert_eq!(page.success, Some(false));
        assert!(page.entries.is_empty());
        assert!(page_is_terminal(&page, 20));
        let request = list_request(20);
        let envelope = build_list_envelope(&request, vec![page], None);
        assert_eq!(envelope["result"], "empty");
        assert_eq!(envelope["entry_count"], 0);
        assert_eq!(envelope["upstream"]["success"], false);
        assert_eq!(envelope["upstream_evidence"], Value::Null);
    }

    #[test]
    fn an_empty_page_is_reported_as_empty_with_a_cursor() {
        let body = br#"{"success":true,"data":{"data":[]}}"#;
        let request = list_request(20);
        let envelope =
            build_list_envelope(&request, vec![page_from(body, Some("application/json"))], None);
        assert_eq!(envelope["result"], "empty");
        assert_eq!(envelope["next_cursor"]["max_id"], Value::Null);
        assert_eq!(envelope["next_cursor"]["has_more"], false);
    }

    #[test]
    fn pagination_parameters_are_exact_and_bounded() {
        let url = list_url(25, 3).unwrap();
        assert_eq!(
            url.as_str(),
            "https://i.buaa.edu.cn/api/appeal?limit=25&page=3"
        );
        assert!(allowed_url(&url));
        assert!(allowed_url(&detail_url(7).unwrap()));
        assert!(!allowed_url(
            &Url::parse("http://i.buaa.edu.cn/api/appeal?limit=25&page=3").unwrap()
        ));
        assert!(!allowed_url(
            &Url::parse("https://i.buaa.edu.cn/api/other?limit=25&page=3").unwrap()
        ));
        assert!(!allowed_url(
            &Url::parse("https://evil.example/api/appeal?limit=25&page=3").unwrap()
        ));
        assert!(!allowed_url(
            &Url::parse("https://i.buaa.edu.cn/api/appeal/7/extra").unwrap()
        ));

        let request = parse_list_input(
            r#"{"token":"synthetic-token","limit":0,"page":1,"max_pages":1}"#,
        )
        .err()
        .unwrap();
        assert_eq!(request.code, "invalid_input");
        let pages = parse_list_input(
            r#"{"token":"synthetic-token","limit":20,"page":1,"max_pages":21}"#,
        )
        .err()
        .unwrap();
        assert_eq!(pages.code, "invalid_input");
    }

    #[test]
    fn incremental_filtering_keeps_new_and_changed_entries_only() {
        let request = ListRequest {
            token: Zeroizing::new("synthetic-token".to_owned()),
            token_source: None,
            limit: 20,
            page: 1,
            max_pages: 1,
            since_id: Some(41),
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::from([(
                42,
                KnownItem {
                    id: 42,
                    status: "Replied".to_owned(),
                    reply_count: 0,
                },
            )]),
            refresh: false,
        };
        let envelope =
            build_list_envelope(&request, vec![page_from(LIST_BODY, Some("application/json"))], None);
        assert_eq!(envelope["entry_count"], 1);
        assert_eq!(envelope["entries"][0]["id"], 42);
        assert_eq!(envelope["entries"][0]["change"], "status_changed");
        assert_eq!(envelope["dedup"]["skipped_at_or_before_since_id"], 1);
        assert_eq!(envelope["dedup"]["kept_changed"], 1);
        assert_eq!(envelope["dedup"]["kept_new"], 0);
        assert_eq!(envelope["next_cursor"]["max_id"], 42);
        assert_eq!(
            envelope["next_cursor"]["max_created_at"],
            "2026-10-22 10:15:00"
        );
    }

    #[test]
    fn an_unchanged_known_entry_is_skipped() {
        let request = ListRequest {
            token: Zeroizing::new("synthetic-token".to_owned()),
            token_source: None,
            limit: 20,
            page: 1,
            max_pages: 1,
            since_id: None,
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::from([(
                42,
                KnownItem {
                    id: 42,
                    status: "Pending".to_owned(),
                    reply_count: 0,
                },
            )]),
            refresh: false,
        };
        let envelope =
            build_list_envelope(&request, vec![page_from(LIST_BODY, Some("application/json"))], None);
        assert_eq!(envelope["entry_count"], 1);
        assert_eq!(envelope["entries"][0]["id"], 41);
        assert_eq!(envelope["dedup"]["skipped_unchanged"], 1);
        assert_eq!(envelope["dedup"]["kept_new"], 1);
    }

    #[test]
    fn changed_known_record_is_not_hidden_by_an_id_cursor() {
        let mut request = list_request(20);
        request.since_id = Some(100);
        request.known.insert(41, KnownItem { id: 41, status: "Pending".into(), reply_count: 1 });
        let envelope = build_list_envelope(&request, vec![page_from(LIST_BODY, Some("application/json"))], None);
        assert_eq!(envelope["entry_count"], 1);
        assert_eq!(envelope["entries"][0]["id"], 41);
        assert_eq!(envelope["entries"][0]["change"], "status_changed");
        assert_eq!(envelope["next_cursor"]["max_id"], 100);
    }

    #[test]
    fn floating_and_offset_cursors_do_not_invent_timezones() {
        let mut request = list_request(20);
        request.since_time = parse_timestamp("2026-10-20T08:30:00Z");
        let facts = analyze_body(LIST_BODY, "synthetic-token-value");
        let (_, entries) =
            parse_envelope(Some("application/json"), facts.document.as_ref()).unwrap();
        assert!(cursor_is_incomparable(&request, &entries));
        request.since_time = parse_timestamp("2026-10-20 08:30:00");
        assert!(!cursor_is_incomparable(&request, &entries));
    }

    #[test]
    fn a_since_time_cursor_preserves_floating_vs_offset_domains() {
        let floating = parse_list_input(
            r#"{"token":"synthetic-token","since_time":"2026-10-20 08:30:00"}"#,
        ).unwrap();
        let accepted = parse_list_input(
            r#"{"token":"synthetic-token","since_time":"2026-10-20T08:30:00+08:00"}"#,
        )
        .unwrap();
        assert!(compare_timestamps(floating.since_time.as_ref().unwrap(), accepted.since_time.as_ref().unwrap()).is_none());
    }

    #[test]
    fn a_missing_token_is_refused_before_any_access() {
        let error = parse_list_input(r#"{"limit":20}"#).err().unwrap();
        assert_eq!(error.code, "authorization_required");
        let blank = parse_list_input(r#"{"token":""}"#).err().unwrap();
        assert_eq!(blank.code, "authorization_required");
        let unsafe_token = parse_list_input(r#"{"token":"bad token"}"#).err().unwrap();
        assert_eq!(unsafe_token.code, "authorization_required");
        let detail = parse_detail_input(r#"{"id":41}"#).err().unwrap();
        assert_eq!(detail.code, "authorization_required");
    }

    #[test]
    fn typed_optional_tokens_use_zeroizing_storage() {
        let mut list: ListInput = serde_json::from_str(
            r#"{"token":"synthetic-secret","operation":"list"}"#,
        ).unwrap();
        let secret: Zeroizing<String> = list.token.take().unwrap();
        assert_eq!(secret.as_str(), "synthetic-secret");
        let detail: DetailInput = serde_json::from_str(
            r#"{"token":"synthetic-secret","id":41}"#,
        ).unwrap();
        let _: &Zeroizing<String> = detail.token.as_ref().unwrap();
        assert!(serde_json::from_str::<ListInput>(r#"{"token":null}"#).unwrap().token.is_none());
        assert!(serde_json::from_str::<ListInput>("{}").unwrap().token.is_none());
    }

    #[test]
    fn documented_object_inputs_reject_positional_arrays() {
        for input in [
            r#"["synthetic-token","list",null,20,1,1,null,null,null,false,false]"#,
            r#"["synthetic-token","detail",null,41,false,false]"#,
        ] {
            assert!(serde_json::from_str::<ListInput>(input).is_err());
            assert!(serde_json::from_str::<DetailInput>(input).is_err());
            assert_eq!(run(input,false).err().unwrap().code,"invalid_input");
        }
        assert!(serde_json::from_str::<OperationSelector>(r#"["list"]"#).is_err());
        for input in [
            r#"{"operation":"list","token":"synthetic-secret","known":[[41,"Pending",0]]}"#,
            r#"{"operation":"list","token":"synthetic-secret","known":[{"id":41,"status":"Pending","reply_count":0},[42,"Pending",0]]}"#,
        ] {
            let error=run(input,false).err().unwrap();
            assert_eq!(error.code,"invalid_input");
            assert!(!error.message.contains("synthetic-secret"));
        }
        // The collection remains an array, but each member must be an object.
        let accepted=parse_list_input(r#"{"operation":"list","token":"synthetic-secret","known":[{"id":41,"status":"Pending","reply_count":0}]}"#).unwrap();
        assert_eq!(accepted.known.len(),1);
        assert_eq!(accepted.known[&41].reply_count,0);
        assert!(parse_detail_input(r#"{"operation":"detail","token":"synthetic-secret","id":41}"#).is_ok());
    }

    #[test]
    fn malformed_and_unknown_field_tokens_fail_without_echo_or_access() {
        // Once a token field is decoded it is owned by Zeroizing, including
        // when a subsequent field or trailing input makes serde fail. These
        // cases check refusal behaviour, not freed allocator memory.
        for input in [
            r#"{"token":"synthetic-secret","limit":"wrong"}"#,
            r#"{"token":"synthetic-secret","unknown":true}"#,
            r#"{"token":"synthetic-secret","token":"duplicate-secret"}"#,
            r#"{"token":"synthetic-secret","limit":20"#,
            r#"{"token":"synthetic-secret"} trailing"#,
        ] {
            let error = parse_list_input(input).err().unwrap();
            assert_eq!(error.code, "invalid_input");
            assert!(!error.message.contains("synthetic-secret"));
            assert!(serde_json::from_str::<ListInput>(input).is_err());
        }
        for input in [
            r#"{"token":"synthetic-secret","id":"wrong"}"#,
            r#"{"token":"synthetic-secret","id":41,"unknown":true}"#,
            r#"{"token":"synthetic-secret","id":41"#,
        ] {
            assert!(serde_json::from_str::<DetailInput>(input).is_err());
            assert_eq!(parse_detail_input(input).err().unwrap().code, "invalid_input");
        }
        for input in [
            r#"{"operation":"list","token":"synthetic-secret","unknown":true}"#,
            r#"{"operation":"detail","token":"synthetic-secret","id":"wrong"}"#,
            r#"{"operation":"list","token":"synthetic-secret"} trailing"#,
        ] {
            let error = run(input, false).err().unwrap();
            assert_eq!(error.code, "invalid_input");
            assert!(!error.message.contains("synthetic-secret"));
        }
    }

    #[test]
    fn an_attachment_download_request_is_unsupported() {
        let error =
            parse_list_input(r#"{"token":"synthetic-token","download_attachments":true}"#)
                .err()
                .unwrap();
        assert_eq!(error.code, "unsupported");
        let detail = parse_detail_input(
            r#"{"token":"synthetic-token","id":41,"download_attachments":true}"#,
        )
        .err()
        .unwrap();
        assert_eq!(detail.code, "unsupported");
    }

    #[test]
    fn a_non_json_body_degrades_with_original_bytes_and_a_hash() {
        let body = b"<html><body>login required</body></html>";
        let page = page_from(body, Some("text/html"));
        let found = page.evidence.clone().expect("evidence");
        assert_eq!(found["fallback_reason"], "unexpected_content");
        assert_eq!(found["content_type"], "text/html");
        assert_eq!(found["byte_length"], body.len());
        assert_eq!(found["sha256"], sha256(body));
        assert_eq!(found["raw_response_base64"], STANDARD.encode(body));
        assert_eq!(found["evidence_kind"], "upstream_http_body");
        let request = list_request(20);
        let envelope = build_list_envelope(&request, vec![page], None);
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["entry_count"], 0);
        assert_eq!(envelope["next_cursor"], Value::Null);
        assert_eq!(envelope["upstream_evidence"]["sha256"], sha256(body));
    }

    #[test]
    fn private_cache_rereads_exact_degraded_body_and_content_type_offline() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-fixture-{}-{}", std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
                    };
        let url = list_url(20, 1).unwrap();
        let bytes = b"<html>synthetic refusal\0\xff</html>";
        let mut original = response(&url, bytes, Some("text/html; charset=UTF-8"));
        original.status = 403;
        cache.save(&original, &ChallengeAssessment::Detected).unwrap();
        let (saved, challenge) = cache.load(&url).unwrap().unwrap();
        assert!(matches!(challenge, ChallengeAssessment::Detected));
        assert_eq!(saved.status, 403);
        assert_eq!(saved.body.as_slice(), &bytes[..]);
        let raw = evidence(response_refusal(&saved, &challenge).unwrap(), &saved, "synthetic-token-value");
        assert_eq!(raw["fallback_reason"], "safety_latched");
        assert_eq!(raw["content_type"], "text/html");
        assert_eq!(raw["content_type_parameters_withheld"],true);
        assert!(raw.get("raw_response_base64").is_none());
        assert_eq!(raw["evidence_kind"], "upstream_http_metadata");
        assert_eq!(raw["byte_length"], bytes.len());
        assert_eq!(raw["sha256"], sha256(bytes));
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_explicit_session_denial_is_a_refusal_and_not_an_empty_listing() {
        let url = list_url(20, 1).unwrap();
        let body = r#"{"success":false,"message":"未登录"}"#.as_bytes();
        let original = response(&url, body, Some("application/json"));
        let facts = analyze_body(&original.body, "synthetic-token-value");
        assert!(facts.session_denied);
        assert!(!facts.token_echo);
        let request = list_request(20);
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        // The upstream flag is reported truthfully, but the refusal is not an
        // empty listing and it carries its own fallback reason.
        assert_eq!(page.success, Some(false));
        assert!(page.entries.is_empty());
        let found = page.evidence.clone().expect("evidence");
        assert_eq!(found["fallback_reason"], "authentication_refused");
        assert!(found.get("raw_response_base64").is_none());
        let envelope = build_list_envelope(&request, vec![page], None);
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["entry_count"], 0);
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["upstream_evidence"]["fallback_reason"], "authentication_refused");
    }

    #[test]
    fn an_ordinary_business_failure_stays_an_empty_listing() {
        let url = list_url(20, 1).unwrap();
        let body = r#"{"success":false,"message":"没有符合条件的数据"}"#.as_bytes();
        let original = response(&url, body, Some("application/json"));
        let facts = analyze_body(&original.body, "synthetic-token-value");
        assert!(!facts.session_denied);
        let request = list_request(20);
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        assert_eq!(page.success, Some(false));
        assert!(page.evidence.is_none());
        let envelope = build_list_envelope(&request, vec![page], None);
        assert_eq!(envelope["result"], "empty");
        assert_eq!(envelope["upstream"]["success"], false);
        assert_eq!(envelope["upstream"]["complete"], true);
    }

    #[test]
    fn a_business_sentence_mentioning_a_refusal_is_not_a_session_denial() {
        // "Duplicate title" is a business rejection whose wording mentions a
        // refusal marker. It must not latch the shared governor.
        let body = br#"{"success":false,"message":"Duplicate title: session expired"}"#;
        let facts = analyze_body(body, "synthetic-token-value");
        assert!(!facts.session_denied);
        assert!(!facts.token_echo);
        // A refusal that carries a short trailing instruction still counts.
        let refusal = "未登录，请重新登录";
        let facts = analyze_body(
            format!("{{\"success\":false,\"message\":\"{refusal}\"}}").as_bytes(),
            "synthetic-token-value",
        );
        assert!(facts.session_denied);
    }

    #[test]
    fn a_token_echo_in_a_duplicated_member_is_still_an_echo() {
        // The parsed document keeps only the last member, so the raw literal
        // scan is the complete evidence.
        let token = "8hT4vN6mQ2sR7cK9pL3xD5aB";
        let body = br#"{"echo":"8hT4vN6mQ2sR7cK9pL3xD5aB","echo":""}"#;
        let facts = analyze_body(body, token);
        assert!(facts.token_echo);
        // A JSON-escaped first character does not hide the echo either: the
        // raw bytes no longer carry the token, and the parsed document keeps
        // only the empty member.
        let escaped = br#"{"echo":"\u0038hT4vN6mQ2sR7cK9pL3xD5aB","echo":""}"#;
        let facts = analyze_body(escaped, token);
        assert!(facts.token_echo);
    }

    #[test]
    fn the_detail_parser_also_refuses_an_explicit_session_denial() {
        let url = detail_url(41).unwrap();
        let body = r#"{"success":false,"message":"请重新登录"}"#.as_bytes();
        let original = response(&url, body, Some("application/json"));
        let facts = analyze_body(&original.body, "synthetic-token-value");
        assert!(facts.session_denied);
        let request = DetailRequest {
            token: Zeroizing::new("synthetic-token-value".to_owned()),
            token_source: None,
            id: 41,
            refresh: false,
        };
        let page = detail_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        assert_eq!(page.success, Some(false));
        assert!(page.entries.is_empty());
        let found = page.evidence.clone().expect("evidence");
        assert_eq!(found["fallback_reason"], "authentication_refused");
    }

    #[test]
    fn short_token_substrings_are_not_projected_by_list_or_detail() {
        let cases = [
            ("q", r#""0q0""#),
            ("abc", r#""0abc0""#),
            ("abc", r#""0\u0061bc0""#),
            ("abc", r#""0YWJj0""#),
            ("a+b", r#""0a\u00252bb0""#),
            ("abc", r#""{\"nested\":\"0\\u0061bc0\"}""#),
        ];
        for (token, title) in cases {
            let token_json = serde_json::to_string(token).unwrap();
            let request = parse_list_input(&format!(r#"{{"token":{token_json}}}"#)).unwrap();
            let detail = parse_detail_input(&format!(r#"{{"token":{token_json},"id":41}}"#)).unwrap();
            let entry = format!(r#"{{"id":41,"title":{title},"content":"ordinary","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}}"#);
            let list_body = format!(r#"{{"success":true,"data":{{"data":[{entry}]}}}}"#);
            let original = response(&list_url(20, 1).unwrap(), list_body.as_bytes(), Some("application/json"));
            let facts = analyze_body(&original.body, token);
            let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
            let envelope = build_list_envelope(&request, vec![page], None);
            assert_eq!(envelope["result"], "degraded", "token={token} title={title}");
            assert_eq!(envelope["entry_count"], 0);
            assert_eq!(envelope["upstream_evidence"]["fallback_reason"], "credential_echo");
            assert!(envelope["upstream_evidence"].get("raw_response_base64").is_none());

            let detail_body = format!(r#"{{"success":true,"data":{entry}}}"#);
            let original = response(&detail_url(41).unwrap(), detail_body.as_bytes(), Some("application/json"));
            let facts = analyze_body(&original.body, token);
            let page = detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts);
            assert!(page.entries.is_empty(), "token={token} title={title}");
            let evidence = page.evidence.expect("withheld detail evidence");
            assert_eq!(evidence["fallback_reason"], "credential_echo");
            assert!(evidence.get("raw_response_base64").is_none());
        }
    }

    #[test]
    fn short_token_raw_fallback_is_withheld_but_safe_entries_remain_visible() {
        let request = parse_list_input(r#"{"token":"abc"}"#).unwrap();
        let detail = parse_detail_input(r#"{"token":"abc","id":41}"#).unwrap();
        let body = b"prefix abc suffix";
        let original = response(&list_url(20, 1).unwrap(), body, Some("text/plain"));
        let facts = analyze_body(body, "abc");
        let list = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        let envelope = build_list_envelope(&request, vec![list], None);
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["upstream_evidence"]["fallback_reason"], "credential_echo");
        assert!(envelope["upstream_evidence"].get("raw_response_base64").is_none());
        let page = detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.entries.is_empty());
        let evidence = page.evidence.expect("withheld detail evidence");
        assert_eq!(evidence["fallback_reason"], "credential_echo");
        assert!(evidence.get("raw_response_base64").is_none());

        let entry = r#"{"id":41,"title":"Quiet hallway","content":"ordinary","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}"#;
        let list_body = format!(r#"{{"success":true,"data":{{"data":[{entry}]}}}}"#);
        let original = response(&list_url(20, 1).unwrap(), list_body.as_bytes(), Some("application/json"));
        let facts = analyze_body(&original.body, "abc");
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        let envelope = build_list_envelope(&request, vec![page], None);
        assert_eq!(envelope["result"], "entries");
        assert_eq!(envelope["entries"][0]["title"], "Quiet hallway");
        assert!(envelope["upstream_evidence"].is_null());

        let detail_body = format!(r#"{{"success":true,"data":{entry}}}"#);
        let original = response(&detail_url(41).unwrap(), detail_body.as_bytes(), Some("application/json"));
        let facts = analyze_body(&original.body, "abc");
        let page = detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.evidence.is_none());
        assert_eq!(page.entries[0]["title"], "Quiet hallway");
    }

    #[test]
    fn encoded_submitted_tokens_never_reach_listing_or_raw_fallback() {
        let url=list_url(20,1).unwrap();
        let request=list_request(20);
        for token in ["opaque-token-value","abc_123"] {
            let padded=STANDARD.encode(token);
            let unpadded=padded.trim_end_matches('=').to_owned();
            for encoded in [&padded,&unpadded] {
                let body=format!(r#"{{"success":false,"message":"\u{:04x}{}"}}"#,encoded.as_bytes()[0],&encoded[1..]);
                let original=response(&url,body.as_bytes(),Some("application/json"));
                let facts=analyze_body(&original.body,token);
                assert!(facts.token_echo);
                let page=list_page(&request,&original,&ChallengeAssessment::Clear,&facts);
                assert!(page.entries.is_empty());
                let evidence=page.evidence.as_ref().unwrap();
                assert_eq!(evidence["fallback_reason"],"credential_echo");
                assert!(evidence.get("raw_response_base64").is_none());
                assert!(!serde_json::to_string(evidence).unwrap().contains(encoded.as_str()));
            }
        }
    }

    #[test]
    fn a_response_that_echoes_the_submitted_token_is_never_published() {
        let url = list_url(20, 1).unwrap();
        let token = "opaque-token-value";
        for body in [
            br#"{"success":false,"message":"opaque-token-value"}"#.as_slice(),
            br#"{"success":true,"data":{"data":[{"id":41,"title":"t","content":"opaque-token-value","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}]}}"#.as_slice(),
        ] {
            let original = response(&url, body, Some("application/json"));
            let facts = analyze_body(&original.body, token);
            assert!(facts.token_echo, "token echo not detected");
            let request = list_request(20);
            let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
            assert!(page.entries.is_empty());
            let found = page.evidence.clone().expect("evidence");
            assert_eq!(found["fallback_reason"], "credential_echo");
            assert!(found.get("raw_response_base64").is_none());
            assert_eq!(found["evidence_kind"], "upstream_http_metadata");
            let envelope = build_list_envelope(&request, vec![page], None);
            assert_eq!(envelope["entry_count"], 0);
            assert!(envelope["upstream_evidence"]["fallback_reason"] == "credential_echo");
        }
        // A percent-encoded echo of the same token is the same disclosure.
        let encoded_token = "opaque+token=value";
        let original = response(
            &url,
            br#"{"message":"opaque%2Btoken%3Dvalue"}"#,
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, encoded_token);
        assert!(facts.token_echo);
        // A JSON-escaped echo is the same disclosure.
        let escaped_token = "opaque\"token";
        let original = response(
            &url,
            br#"{"message":"opaque\"token"}"#,
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, escaped_token);
        assert!(facts.token_echo);
    }

    #[test]
    fn an_ordinary_body_is_not_mistaken_for_a_token_echo() {
        let url = list_url(20, 1).unwrap();
        let body = br#"{"success":true,"data":{"data":[{"id":41,"title":"t","content":"ordinary","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}]}}"#;
        let original = response(&url, body, Some("application/json"));
        let facts = analyze_body(&original.body, "opaque-token-value");
        assert!(!facts.token_echo);
        assert!(!facts.session_denied);
    }

    #[test]
    fn cookie_issuing_originals_are_refused_before_projection_and_cache() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-cookie-admission-{}-{}", std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
                    };
        let url = list_url(20, 1).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::SET_COOKIE, "x=q".parse().unwrap());
        for body in [
            br#"{"success":true,"data":{"value":"q"}}"#.as_slice(),
            "{\"success\":false,\"message\":\"未登录\",\"value\":\"q\"}".as_bytes(),
        ] {
            let original = response(&url, body, Some("application/json"));
            let facts = analyze_body(body, "synthetic-bearer");
            let denied = body == "{\"success\":false,\"message\":\"未登录\",\"value\":\"q\"}".as_bytes();
            assert_eq!(facts.session_denied, denied);
            let result = admit_response(&cache, &original, &ChallengeAssessment::Clear,
                &facts, net::issues_session_cookie(&headers), |_, _, _| -> Result<(), Error> {
                    panic!("cookie-bearing original reached projection");
                });
            assert_eq!(result.unwrap_err().code, "session_cookie_issued");
            assert!(cache.load(&url).unwrap().is_none());
            assert_eq!(facts.session_denied, denied);
        }
        let original = response(&url, br#"{"success":true,"data":[]}"#, Some("application/json"));
        let facts = analyze_body(&original.body, "synthetic-bearer");
        let length = admit_response(&cache, &original, &ChallengeAssessment::Clear,
            &facts, net::issues_session_cookie(&reqwest::header::HeaderMap::new()),
            |response, _, _| Ok(response.body.len())).unwrap();
        assert_eq!(length, original.body.len());
        assert!(cache.load(&url).unwrap().is_some());
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_cache_is_preserved_but_not_published_without_cookie_admission() {
        for version in [2,3] {
            for rejected in [false,true] {
                let root=std::env::temp_dir().join(format!("buaa-ihome-legacy-cookie-{}-{}",std::process::id(),SEQUENCE.fetch_add(1,AtomicOrdering::Relaxed)));
                std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
                let directory=root.join("cache");let governor_directory=root.join("governor");
                std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
                std::fs::DirBuilder::new().mode(0o700).create(&governor_directory).unwrap();
                let cache=ResponseCache {directory:governor::open_directory(&directory,false,true).unwrap()};
                let url=list_url(20,1).unwrap();
                let mut original=response(&url,br#"{"name":"opaque-short"}"#,Some("application/json"));
                if rejected {original.status=403;}
                cache.save(&original,&ChallengeAssessment::Clear).unwrap();
                let path=directory.join(ResponseCache::name(&url));
                let mut legacy:Cached=serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                legacy.version=version;
                let bytes=serde_json::to_vec(&legacy).unwrap();
                std::fs::write(&path,&bytes).unwrap();
                let error=cache.get(&url,"different-submitted-token",false,false,|_,_,_|->Result<(),Error>{panic!("unreviewed legacy body reached output")}).unwrap_err();
                assert_eq!(error.code, if rejected { "safety_latched" } else { "cached_response_unreviewed" });
                assert!(!error.message.contains("opaque-short"));
                assert_eq!(std::fs::read(&path).unwrap(),bytes);
                let governor=Governor::isolated_for_test(&governor_directory).unwrap();
                assert_eq!(governor.status().unwrap().safety_latched, false);
                drop(governor);drop(cache);std::fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[test]
    fn a_cached_authentication_rejection_is_refused_without_replay() {
        let root = std::env::temp_dir().join(format!(
            "buaa-ihome-cached-rejection-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let cache_directory = root.join("cache");
        let governor_directory = root.join("governor");
        std::fs::DirBuilder::new().mode(0o700).create(&cache_directory).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&governor_directory).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        // A cached HTTP 403 with an ordinary JSON body has no challenge
        // assessment, so it used to be replayed without any safety
        // observation at all.
        let mut original = response(&url, br#"{"message":"forbidden"}"#, Some("application/json"));
        original.status = 403;
        cache.save(&original, &ChallengeAssessment::Clear).unwrap();
        let error = cache
            .get(&url, "synthetic-token-value", false, false, |_, _, _| {
                Ok::<(), Error>(())
            })
            .unwrap_err();
        assert_eq!(error.code, "safety_latched");
        drop(cache);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_cached_session_denial_is_refused_without_replay() {
        let root = std::env::temp_dir().join(format!(
            "buaa-ihome-cached-denial-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let cache_directory = root.join("cache");
        let governor_directory = root.join("governor");
        std::fs::DirBuilder::new().mode(0o700).create(&cache_directory).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&governor_directory).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        let original = response(
            &url,
            r#"{"success":false,"message":"未登录"}"#.as_bytes(),
            Some("application/json"),
        );
        cache.save(&original, &ChallengeAssessment::Clear).unwrap();
        let error = cache
            .get(&url, "synthetic-token-value", false, false, |_, _, _| {
                Ok::<(), Error>(())
            })
            .unwrap_err();
        assert_eq!(error.code, "safety_latched");
        drop(cache);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_cached_body_that_echoes_the_token_is_removed_and_never_published() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-echo-cache-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
                    };
        let url = list_url(20, 1).unwrap();
        let original = response(&url, br#"{"message":"opaque-token-value"}"#, Some("application/json"));
        cache.save(&original, &ChallengeAssessment::Clear).unwrap();
        let outcome = cache
            .get(&url, "opaque-token-value", false, false, |response, _, facts| {
                assert!(facts.token_echo);
                assert!(!response.body.is_empty());
                Ok::<(), Error>(())
            })
            .unwrap();
        assert_eq!(outcome, ());
        // The echoed body is not kept on disk.
        assert!(cache.load(&url).unwrap().is_none());
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_incomplete_traversal_keeps_the_admitted_pages_and_advances_no_cursor() {
        let request = list_request(20);
        let page = page_from(LIST_BODY, Some("application/json"));
        let envelope = build_list_envelope(&request, vec![page], Some("offline_miss"));
        assert_eq!(envelope["result"], "partial");
        assert_eq!(envelope["entry_count"], 2);
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["upstream"]["incomplete"], true);
        assert_eq!(envelope["upstream"]["incomplete_reason"], "offline_miss");
        // The incremental cursor is not advanced: the unread page could still
        // hold records below the admitted maximum.
        assert_eq!(envelope["next_cursor"], Value::Null);
        assert_eq!(envelope["entries"][0]["id"], 41);
    }

    #[test]
    fn fallback_inspection_covers_relative_urls_string_bodies_and_leading_text() {
        let url=list_url(20,1).unwrap();
        for (mime,body) in [
            ("application/json",br#"{"redirect":"/web/?token=synthetic-secret"}"#.as_slice()),
            ("application/json",br#"{"payload":"\"Bearer synthetic-secret\""}"#.as_slice()),
            ("application/json",br#"{"url":"//files.invalid/?secret=synthetic-secret"}"#.as_slice()),
            ("text/plain",br#""Bearer synthetic-secret""#.as_slice()),
            ("text/html; charset=UTF-8",b"Sign in<input name=\"token\" value=\"synthetic-secret\">".as_slice()),
        ] {
            let original=response(&url,body,Some(mime));
            let found=evidence(FallbackReason::UpstreamShape,&original,"synthetic-token-value");
            assert!(found.get("raw_response_base64").is_none());
            assert_eq!(found["evidence_kind"],"upstream_http_metadata");
            assert_eq!(found["sha256"],sha256(body));
        }
        let ordinary=br#"{"message":"maintenance","count":2}"#;
        let original=response(&url,ordinary,Some("application/json"));
        assert_eq!(evidence(FallbackReason::UpstreamShape,&original,"synthetic-token-value")["raw_response_base64"],STANDARD.encode(ordinary));
        let plain=b"ordinary notice";
        let original=response(&url,plain,Some("text/plain"));
        assert_eq!(evidence(FallbackReason::UpstreamParse,&original,"synthetic-token-value")["raw_response_base64"],STANDARD.encode(plain));
        let html=b"<p>ordinary notice</p>";
        let original=response(&url,html,Some("text/html"));
        assert_eq!(evidence(FallbackReason::UpstreamParse,&original,"synthetic-token-value")["raw_response_base64"],STANDARD.encode(html));
    }

    #[test]
    fn all_retry_after_fields_survive_original_lease_body_failure() {
        let root=std::env::temp_dir().join(format!("buaa-ihome-headers-{}-{}",std::process::id(),SEQUENCE.fetch_add(1,AtomicOrdering::Relaxed)));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let governor=Governor::isolated_for_test(&root.join("shared")).unwrap();
        let mut lease=governor.try_acquire(governor::RequestKind::Interactive).unwrap();
        let mut headers=reqwest::header::HeaderMap::new();
        headers.append("retry-after",reqwest::header::HeaderValue::from_static("60"));
        headers.append("retry-after",reqwest::header::HeaderValue::from_static("7200"));
        headers.append("retry-after",reqwest::header::HeaderValue::from_static("invalid"));
        observe_response_headers(&mut lease,429,&headers,true).unwrap();
        lease.finish(Outcome::Http {status:429,retry_after:Some("60"),challenge:false,network_failure:true}).unwrap();
        let state=governor.status().unwrap();
        assert!(state.cooldown_wait.as_secs()>7100);
        assert!(!state.safety_latched);
        assert_eq!(state.consecutive_network_failures,1);
        drop(governor); std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_content_types_never_establish_clear_body_admission() {
        for types in [["application/json","text/html"],["text/html","application/json"],["text/plain","text/plain"]] {
            let mut headers=reqwest::header::HeaderMap::new();
            for value in types {headers.append("content-type",reqwest::header::HeaderValue::from_str(value).unwrap());}
            let collected=collect_headers(&headers).unwrap();
            let assessment=assess_response_body(br#"{"success":false}"#,collected.get("content-type").map(String::as_str),true);
            assert!(matches!(assessment,ChallengeAssessment::Unreviewed));
            assert!(collected["content-type"].contains(", "));
        }
        assert!(matches!(assess_response_body(br#"{"success":false}"#,Some("application/json"),true),ChallengeAssessment::Clear));
    }

    #[test]
    fn cached_confirmed_challenge_refuses_without_touching_production() {
        let root=std::env::temp_dir().join(format!("buaa-ihome-marker-{}-{}",std::process::id(),SEQUENCE.fetch_add(1,AtomicOrdering::Relaxed)));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let cache_directory=root.join("cache");
        let governor_directory=root.join("governor");
        std::fs::DirBuilder::new().mode(0o700).create(&cache_directory).unwrap();
        std::fs::DirBuilder::new().mode(0o700).create(&governor_directory).unwrap();
        let cache=ResponseCache {directory:governor::open_directory(&cache_directory,false,true).unwrap()};
        let url=list_url(20,1).unwrap();
        let body=b"<html>cached refusal</html>";
        let original=response(&url,body,Some("text/html"));
        cache.save(&original,&ChallengeAssessment::Detected).unwrap();
        // A cache hit on a confirmed challenge refuses without any request.
        let error=cache.get(&url,"synthetic-token",false,false,|_,_challenge,_facts|{
            Ok::<(),Error>(())
        }).unwrap_err();
        assert_eq!(error.code,"safety_latched");
        let governor=Governor::isolated_for_test(&governor_directory).unwrap();
        assert!(!governor.status().unwrap().safety_latched);
        drop(cache); drop(governor);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cache_race_under_a_held_lease_settles_the_same_lock() {
        let root=std::env::temp_dir().join(format!("buaa-ihome-race-{}-{}",std::process::id(),SEQUENCE.fetch_add(1,AtomicOrdering::Relaxed)));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let cache_directory=root.join("cache");
        std::fs::DirBuilder::new().mode(0o700).create(&cache_directory).unwrap();
        let cache=ResponseCache {directory:governor::open_directory(&cache_directory,false,true).unwrap()};
        let url=list_url(20,1).unwrap();
        let body=b"<html>cached refusal</html>";
        let original=response(&url,body,Some("text/html"));
        cache.save(&original,&ChallengeAssessment::Detected).unwrap();
        let governor=Governor::isolated_for_test(&root.join("shared")).unwrap();
        let transport=Transport::open_isolated(governor).unwrap();
        let outcome=transport.fetch(&cache,&url,"synthetic-token",false,|_,challenge,_facts|{
            assert!(matches!(challenge,ChallengeAssessment::Detected));
            Ok::<(),Error>(())
        });
        // The cache race settles the held lease without sending a request, so
        // no network access is possible in this regression.
        assert!(outcome.is_ok());
        let status=transport.governor.status().unwrap();
        assert!(!status.safety_latched);
        drop(transport); drop(cache);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_json_is_withheld_without_collapsing_duplicate_or_escaped_keys() {
        let url=list_url(20,1).unwrap();
        for body in [
            br#"{"token":"synthetic-secret","password":"synthetic-password"}"#.as_slice(),
            br#"{"outer":[{"to\u006ben":"synthetic-secret"}]}"#.as_slice(),
            br#"{"outer":{"token":"synthetic-secret"},"outer":{"message":"safe"}}"#.as_slice(),
            br#"{"nested":"{\"cookie\":\"synthetic-secret\"}"}"#.as_slice(),
            br#"{"link":"https://files.example.invalid/a?access%5Ftoken=synthetic-secret"}"#.as_slice(),
        ] {
            let original=response(&url,body,Some("application/json"));
            let found=evidence(FallbackReason::UpstreamShape,&original,"synthetic-token-value");
            assert!(found.get("raw_response_base64").is_none());
            assert_eq!(found["evidence_kind"],"upstream_http_metadata");
            assert_eq!(found["sha256"],sha256(body));
            assert_eq!(page_meta(&original,0,"synthetic-token-value")["response_body_sha256"],sha256(body));
        }
        let safe=br#"{"message":"ordinary server maintenance","nested":[{"code":7}]}"#;
        let original=response(&url,safe,Some("application/json"));
        assert_eq!(evidence(FallbackReason::UpstreamShape,&original,"synthetic-token-value")["raw_response_base64"],STANDARD.encode(safe));
    }

    #[test]
    fn credential_urls_are_not_projected_as_attachments() {
        let mut urls=Vec::new();
        for text in [
            "https://reader:synthetic-password@files.example.invalid/photo.jpg",
            "https://files.example.invalid/photo.jpg?access%5ftoken=synthetic-secret",
            "https://files.example.invalid/photo.jpg#token=synthetic-secret",
        ] { collect_declared_urls(&json!(text),&mut urls,0); }
        assert!(urls.is_empty());
        collect_declared_urls(&json!("https://files.example.invalid/photo.jpg?size=large"),&mut urls,0);
        assert_eq!(urls,vec!["https://files.example.invalid/photo.jpg?size=large"]);
    }

    #[test]
    fn cached_private_originals_keep_hashes_without_exporting_credentials_or_mime_parameters() {
        let directory=std::env::temp_dir().join(format!("buaa-ihome-private-fixture-{}-{}",std::process::id(),SEQUENCE.fetch_add(1,AtomicOrdering::Relaxed)));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let cache=ResponseCache {directory:governor::open_directory(&directory,false,true).unwrap()};
        let url=list_url(20,1).unwrap();
        let body=br#"{"nested":{"password":"synthetic-secret"}}"#;
        let original=response(&url,body,Some("application/json; sessionid=synthetic-secret"));
        cache.save(&original,&ChallengeAssessment::Clear).unwrap();
        let (saved,assessment)=cache.load(&url).unwrap().unwrap();
        assert!(matches!(assessment,ChallengeAssessment::Clear));
        assert_eq!(saved.body,body);
        assert_eq!(saved.headers["content-type"],"application/json; sessionid=synthetic-secret");
        let found=evidence(FallbackReason::UpstreamShape,&saved,"synthetic-token-value");
        assert!(found.get("raw_response_base64").is_none());
        assert_eq!(found["content_type"],"application/json");
        assert_eq!(found["content_type_parameters_withheld"],true);
        assert_eq!(found["sha256"],sha256(body));
        assert_eq!(page_meta(&saved,0,"synthetic-token-value")["cache_status"],"hit");
        assert!(!page_meta(&saved,0,"synthetic-token-value").to_string().contains("synthetic-secret"));
        drop(cache); std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unreviewed_challenge_is_not_a_captcha_claim_and_withholds_raw_body() {
        let url=list_url(20,1).unwrap();
        let original=response(&url,b"<html>private-token</html>",Some("application/xhtml+xml"));
        let assessment=assess_challenge_body(&original.body,Some("application/xhtml+xml"),true);
        let reason=response_refusal(&original,&assessment).unwrap();
        assert_eq!(reason,FallbackReason::ChallengeUnreviewed);
        let value=evidence(reason,&original,"synthetic-token-value");
        assert_eq!(value["fallback_reason"],"challenge_unreviewed");
        assert!(value.get("raw_response_base64").is_none());
        assert_eq!(value["sha256"],sha256(&original.body));
        assert!(!matches!(assessment,ChallengeAssessment::Detected));
    }

    #[test]
    fn http_refusals_are_evidence_not_empty_lists() {
        let url = list_url(20, 1).unwrap();
        let mut response = response(&url, b"busy", Some("text/plain; charset=UTF-8"));
        response.status = 429;
        let reason = response_refusal(&response, &ChallengeAssessment::Clear).unwrap();
        let evidence = evidence(reason, &response, "synthetic-token-value");
        assert_eq!(evidence["fallback_reason"], "rate_limited");
        assert_eq!(evidence["http_status"], 429);
        assert_eq!(evidence["content_type"], "text/plain");
    }

    #[test]
    fn a_missing_content_type_is_reported_as_null_not_as_the_expected_one() {
        let body = b"not json at all";
        let page = page_from(body, None);
        let found = page.evidence.clone().expect("evidence");
        assert_eq!(found["fallback_reason"], "upstream_parse");
        assert_eq!(found["content_type"], Value::Null);
        assert_eq!(found["byte_length"], body.len());
        assert_eq!(found["sha256"], sha256(body));
    }

    #[test]
    fn a_json_body_with_a_foreign_shape_degrades_as_upstream_shape() {
        let body = br#"{"success":true,"data":{"data":[{"id":"not-a-number"}]}}"#;
        let page = page_from(body, Some("application/json"));
        let found = page.evidence.clone().expect("evidence");
        assert_eq!(found["fallback_reason"], "upstream_shape");
        assert_eq!(found["content_type"], "application/json");
        assert_eq!(found["raw_response_base64"], STANDARD.encode(body));
    }

    #[test]
    fn timestamps_are_parsed_without_rewriting_the_canonical_value() {
        let base = parse_timestamp("2026-10-20 08:30:00").unwrap();
        let zoned = parse_timestamp("2026-10-20T08:30:00Z").unwrap();
        assert!(compare_timestamps(&base, &zoned).is_none());
        let earlier = parse_timestamp("2026-10-20T08:30:00+08:00").unwrap();
        assert_eq!(compare_timestamps(&earlier, &zoned), Some(Ordering::Less));
        let fractional = parse_timestamp("2026-10-20T08:30:00.123Z").unwrap();
        assert_eq!(compare_timestamps(&fractional, &zoned), Some(Ordering::Greater));
        assert!(parse_timestamp("not a timestamp").is_none());
        assert!(parse_timestamp("2026-10-20").is_none());
        assert!(parse_timestamp("2026-02-30 08:00:00").is_none());
    }

    #[test]
    fn a_credential_bearing_content_type_is_withheld_in_list_detail_and_cache_replay() {
        let page_url = list_url(20, 1).unwrap();
        let entry_url = detail_url(41).unwrap();
        let token = "synthetic-bearer";
        let body = br#"{"success":true,"data":{"data":[],"notice":"ordinary maintenance"}}"#;
        let list = ListRequest {
            token: Zeroizing::new(token.to_owned()), token_source: None,
            limit: 20, page: 1, max_pages: 1, since_id: None,
            since_time_raw: None, since_time: None, known: BTreeMap::new(), refresh: false,
        };
        let detail = DetailRequest {
            token: Zeroizing::new(token.to_owned()), token_source: None, id: 41, refresh: false,
        };
        // The submitted token is a token-shaped MIME subtype, a parameter and a
        // percent or case-mangled spelling: every projection of that header
        // value must report it as withheld instead of echoing it.
        for header in [
            "application/synthetic-bearer",
            "APPLICATION/SYNTHETIC-BEARER",
            "application/x-received; profile=synthetic-bearer",
            "text/plain; note=%73%79%6E%74%68%65%74%69%63%2D%62%65%61%72%65%72",
        ] {
            let facts = analyze_body(body, token);
            assert!(!facts.token_echo, "ordinary body is not an echo");
            for outcome in [
                list_page(&list, &response(&page_url, body, Some(header)), &ChallengeAssessment::Clear, &facts),
                detail_page(&detail, &response(&entry_url, body, Some(header)), &ChallengeAssessment::Clear, &facts),
            ] {
                let evidence = outcome.evidence.as_ref().expect("degraded evidence");
                assert_eq!(evidence["fallback_reason"], "unexpected_content");
                assert_eq!(evidence["content_type"], Value::Null);
                assert_eq!(evidence["content_type_parameters_withheld"], true);
                assert!(!serde_json::to_string(evidence).unwrap().contains(token));
                assert!(!serde_json::to_string(&outcome.meta).unwrap().contains(token));
                assert_eq!(outcome.meta["content_type"], Value::Null);
                assert_eq!(outcome.meta["content_type_parameters_withheld"], true);
            }
        }
        // A safe header still projects its essence and parameters stay marked.
        let safe = response(&page_url, body, Some("application/json; charset=utf-8"));
        let facts = analyze_body(body, token);
        let page = list_page(&list, &safe, &ChallengeAssessment::Clear, &facts);
        assert_eq!(page.success, Some(true));
        assert!(page.evidence.is_none());
        assert_eq!(page.meta["content_type"], "application/json");
        assert_eq!(page.meta["content_type_parameters_withheld"], true);
        // A header that merely names the token shape is the same withholding on
        // cache replay: the cached original is never republished as observed.
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-mime-{}-{}", std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
                    };
        let stored = response(&page_url, body, Some("application/synthetic-bearer"));
        cache.save(&stored, &ChallengeAssessment::Clear).unwrap();
        let outcome = cache
            .get(&page_url, token, false, false, |saved, challenge, facts| {
                assert_eq!(saved.cache_status, CacheStatus::Hit);
                Ok::<PageOutcome, Error>(list_page(&list, saved, challenge, facts))
            })
            .unwrap();
        assert_eq!(outcome.meta["content_type"], Value::Null);
        assert_eq!(outcome.meta["content_type_parameters_withheld"], true);
        assert!(!serde_json::to_string(&outcome.meta).unwrap().contains(token));
        let evidence = outcome.evidence.as_ref().expect("degraded evidence");
        assert_eq!(evidence["content_type"], Value::Null);
        assert!(!serde_json::to_string(evidence).unwrap().contains(token));
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn credential_bearing_html_metadata_withholds_raw_body_but_ordinary_meta_stays_safe() {
        let url = list_url(20, 1).unwrap();
        let token = "synthetic-bearer";
        for body in [
            b"<html><head><meta name=\"csrf-token\" content=\"fresh-opaque-secret\"></head><body>sign in</body></html>".as_slice(),
            b"<html><body><meta http-equiv=\"set-cookie\" content=\"session=abc\"><p>denied</p></body></html>".as_slice(),
            b"<html><head><meta property=\"session-state\" content=\"x\"></head><body>retry</body></html>".as_slice(),
            b"<html><body><meta itemprop=\"ticket\" content=\"y\">lookup failed</body></html>".as_slice(),
        ] {
            let original = response(&url, body, Some("text/html"));
            let facts = analyze_body(body, token);
            assert!(!facts.token_echo);
            let found = evidence(FallbackReason::UpstreamParse, &original, token);
            assert!(found.get("raw_response_base64").is_none());
            assert_eq!(found["evidence_kind"], "upstream_http_metadata");
            assert_eq!(found["sha256"], sha256(body));
            assert_eq!(found["content_type"], "text/html");
            let envelope = build_list_envelope(&list_request(20), vec![PageOutcome {
                meta: page_meta(&original, 0, token),
                success: None,
                evidence: Some(found),
                entries: Vec::new(),
            }], None);
            assert!(envelope["upstream_evidence"].get("raw_response_base64").is_none());
        }
        // Ordinary metadata and inert controls keep the raw body admissible.
        for body in [
            b"<html><head><meta name=\"description\" content=\"appeal board\"><meta name=\"viewport\" content=\"width=device-width\"></head><body>pending</body></html>".as_slice(),
            b"<html><head><meta charset=\"utf-8\"></head><body>temporarily unavailable</body></html>".as_slice(),
            b"<html><body><meta name=\"color-scheme\" content=\"light dark\">notice</body></html>".as_slice(),
        ] {
            let original = response(&url, body, Some("text/html"));
            let found = evidence(FallbackReason::UpstreamParse, &original, token);
            assert_eq!(found["raw_response_base64"], STANDARD.encode(body));
            assert_eq!(found["evidence_kind"], "upstream_http_body");
        }
        // Credential-marked input controls were already withheld; a meta-only
        // document is the new regression.
        let controls = b"<html><body><input name=\"token\" value=\"x\"></body></html>";
        let original = response(&url, controls, Some("text/html"));
        assert!(evidence(FallbackReason::UpstreamParse, &original, token)
            .get("raw_response_base64")
            .is_none());
    }

    #[test]
    fn the_schema_matches_the_runtime_contract() {
        let contract = schema();
        assert_eq!(
            contract["$defs"]["list_input"]["properties"]["download_attachments"]["default"],
            false
        );
        assert_eq!(
            contract["$defs"]["list_input"]["properties"]["since_id"]["type"][0],
            "integer"
        );
        assert_eq!(
            contract["list"]["output"]["properties"]["result"]["enum"],
            json!(["entries", "empty", "partial", "degraded"])
        );
        assert_eq!(
            contract["detail"]["output"]["properties"]["result"]["enum"],
            json!(["appeal", "not_found", "degraded"])
        );
        assert!(
            contract["unknown"]["attachment_download"]
                .as_str()
                .unwrap()
                .contains("UNKNOWN")
        );
        assert_eq!(
            contract["list"]["output"]["properties"]["credential_source"]["enum"][3],
            Value::Null
        );
        assert_eq!(
            contract["$defs"]["list_entry"]["required"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        assert_eq!(
            contract["$defs"]["entry"]["required"].as_array().unwrap().len(),
            10
        );
    }
}

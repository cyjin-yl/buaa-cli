//! Governed, read-only adapter for the ihome appeal board (`i.buaa.edu.cn`).
//!
//! What this module implements, and what it deliberately does not:
//!
//! * Business reads use exactly two documented endpoints over HTTPS only:
//!   `GET /api/appeal?limit=<int>&page=<int>` (listing) and
//!   `GET /api/appeal/<id>` (one appeal). Every request carries
//!   `Accept: application/json`, `Authorization: Bearer <token>` and
//!   `Referer: https://i.buaa.edu.cn/web/`.
//! * Legacy list/detail operations accept an explicit bearer token and an
//!   optional caller declaration of its provenance. A missing token is refused
//!   as `authorization_required` before any cache or network access.
//!   The separate session operation performs one explicitly authorized CAS
//!   login and one selected read, with exact `LOGIN <username> ihome` intent.
//!   It consumes the reviewed `/web/` fragment token without fetching that
//!   terminal URL. Only the exact reviewed HTTP `/api/authLogin` callback is
//!   upgraded to HTTPS; no plaintext request or arbitrary same-host path is
//!   admitted. Disabled reads perform no account-state or network I/O.
//!   Typed decoding wraps each token immediately in `Zeroizing`, including
//!   tokens decoded before a subsequent malformed or unknown field fails.
//!   Dispatch reads only the operation and ignores the other fields without
//!   constructing a generic JSON value or reserializing credentials. The
//!   caller's input buffer, serde parser scratch space, and reqwest/TLS-owned
//!   copies are outside this module's zeroization guarantee.
//! * Legacy remote reads keep their existing shared-governor lease through
//!   body processing. Session authentication and its one business read share
//!   one Authentication lease; they never cache, persist credentials, paginate,
//!   refresh or retry. A `429`/`Retry-After`
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
//!   Legacy token reads also retain admitted safe bytes in a private,
//!   credential-scoped cache for offline reuse. Session reads never cache.
//! * The supplied bearer token is never echoed. Every response body and
//!   decoded JSON string is inspected for the token and the reversible forms
//!   supported by `net::carries_secret` before projection or export. Matching
//!   is conservative: even an accidental substring match, especially with a
//!   short token, withholds the body rather than risking disclosure.
//!   A body that echoes the token is refused as `credential_echo`: no entry is
//!   projected, no raw bytes are exported and the body is not cached.
//!   Session output additionally guards the username, password, transmitted
//!   cookie headers and current/retired cookie values, including MIME echoes.
//!   The complete invocation additionally guards the credential values of
//!   every fresh response's `Set-Cookie` headers: they are reviewed from the
//!   raw header map before collection discards them, retained across pages
//!   to screen later fresh and cached bodies and MIME, and never adopted or
//!   transmitted. Before the consumer envelope is published, every retained
//!   page is screened once more against the complete invocation history: a
//!   value first issued by a later page is credential material wherever an
//!   earlier page already carried it, so that page's records are withheld,
//!   the traversal never reports complete, and a cached admission whose
//!   content matches is removed. An unreviewable value refuses projection,
//!   and no cookie-issuing response is written to the replayable cache.
//!   Responses whose nested token inspection exceeds its bound are withheld as
//!   unreviewed, without claiming an echo or an authentication refusal.
//! * An explicit application-level authentication refusal (a root-level
//!   message that states the session is not authenticated) is not an empty
//!   listing. It is reported as `authentication_refused` and it settles the
//!   original lease as a credential rejection, so the shared governor latches
//!   and the next request requires an explicit resume. Business acceptance
//!   separately requires numeric `code=20000` and Boolean `success=true`;
//!   a negative or unknown envelope degrades instead of inventing emptiness.
//! * A cached HTTP `401`/`403`, and a cached application-level refusal, are
//!   published to the shared governor on every cache read, so a replay of the
//!   same rejection cannot leave the governor unlatched.
//! * When a later page of a multi-page traversal cannot be fetched, the pages
//!   that were already admitted are preserved and reported as a `partial`
//!   traversal. The traversal is never reported as complete and the
//!   incremental cursor is not advanced.
//! * Attachments are never downloaded. No modern attachment-download contract
//!   has been reviewed; legacy `php-ihome` upload/attachment routes are not
//!   evidence about the modern appeal service, so no attachment
//!   endpoint is guessed here. Only URLs that the upstream record itself
//!   declares are reported, with their presence, and they are never fetched.
//! * WebVPN URL encryption is an upstream client-side detail and is not
//!   implemented; only direct HTTPS to `i.buaa.edu.cn` is used. The current
//!   idle window is unknown and never blocks, delays or rewrites a request.
//! * Missing titles remain absent; supplied titles and dates are preserved.
//!   Source pagination must match the requested page, limit and record count.
//!   Missing/inconsistent facts, changing totals and duplicate ids stop the
//!   traversal without advancing a cursor or claiming complete history.
//! * A detail read requires an explicit source-shaped appeal id. The id is
//!   never defaulted: an absent or null id is refused, `0` is refused as an
//!   invented placeholder before any cache or network access, and an admitted
//!   URL path must be the canonical decimal form of a positive id.
//!   The detail envelope states completeness explicitly. `complete` is true
//!   only when the requested record was projected from an accepted positive
//!   envelope; a withheld, unparsable or mismatched response keeps its
//!   `fallback_reason` as `incomplete_reason`; and an accepted envelope that
//!   supplies no record for the requested id is `not_found` with
//!   `incomplete_reason=record_not_returned`, because an empty answer cannot
//!   be distinguished from an account-scoped visibility limit here.
//!
//! Source protocol reference (not current-deployment proof):
//! https://github.com/BUAASubnet/UBAA/blob/e8a397fcb35a68147eee65a94c66ffb84e2f09fe/shared/src/commonMain/kotlin/cn/edu/ubaa/api/feature/IhomeProtocol.kt
//! https://github.com/BUAASubnet/UBAA/blob/e8a397fcb35a68147eee65a94c66ffb84e2f09fe/shared/src/commonMain/kotlin/cn/edu/ubaa/api/feature/IhomeUpstreamClient.kt
//!
//! Nothing here has been exercised against the live campus service; the
//! endpoint contract is the documented one and the online acceptance of this
//! adapter is still unverified.

use crate::governor::{self, Governor, Outcome};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use crate::net::{self, CacheStatus, Error, Response};
use crate::recordings::session::{self as cas, CasService, SsoCredentials};
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

/// The appeal id is a source fact, never a default. An absent id is refused
/// instead of being materialized as `0`, and `0` cannot address a source
/// record: the listing publishes positive record identifiers, so a zero id can
/// only be an invented placeholder for a record the caller never identified.
const MIN_APPEAL_ID: u64 = 1;

fn missing_appeal_id() -> Error {
    invalid_input("an explicit upstream appeal id is required; it is never defaulted")
}

fn source_appeal_id(id: u64) -> Result<u64, Error> {
    if id < MIN_APPEAL_ID {
        return Err(invalid_input(
            "id must be a positive upstream appeal id observed from the source",
        ));
    }
    Ok(id)
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
        "ihome list/detail require an explicit bearer token; the separate session operation authenticates once",
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

/// One screening predicate over raw response bytes: the sign-on material and
/// the issued-cookie values that must never reach a projection.
type Screening<'a> = &'a dyn Fn(&[u8]) -> bool;

// Construct literal JSON values ourselves: serde_json's Value visitor treats
// a reserved first member as RawValue when that feature is enabled. Inspect
// every member before last-member-wins insertion, including duplicates.
struct TokenInspection<'a> {
    token: &'a str,
    authentication: Option<Screening<'a>>,
    scan_decoded: bool,
    echo: bool,
    incomplete: bool,
}

impl TokenInspection<'_> {
    fn carries_secret(&self, bytes: &[u8]) -> bool {
        net::carries_secret(bytes, self.token)
            || self.authentication.is_some_and(|contains| contains(bytes))
    }

    fn scalar(&mut self, value: &Value) {
        // Only a session read has additional authentication material. Check
        // source numbers in the exact spelling a consumer would receive.
        if self.authentication.is_some() && !self.echo {
            self.echo = net::json_scalar_matches(value, |bytes| self.carries_secret(bytes));
        }
    }

    fn inspect(&mut self, text: &str, embedded_depth: usize, allow_embedded: bool) {
        if self.token.is_empty() && self.authentication.is_none() {
            return;
        }
        if self.scan_decoded && !self.echo {
            self.echo = self.carries_secret(text.as_bytes());
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
            let valid = LiteralSeed {
                inspection: self,
                embedded_depth: embedded_depth + 1,
                remaining_containers: MAX_LITERAL_CONTAINERS,
                build: false,
            }
            .deserialize(&mut decoder)
            .is_ok()
                && decoder.end().is_ok();
            if !valid {
                // Ordinary prose may fail JSON syntax, but an exhausted
                // inspection budget is independent evidence. Keep the
                // visitor/decoder-boundary `incomplete` fact even when this
                // optional document's echo observation is discarded.
                self.echo = prior;
            }
        }
    }
}

// Match serde_json's normal recursion allowance: 127 enclosing containers
// may still contain a scalar, but entering the next container exhausts its
// default 128-entry guard. Keep this budget separate from the 32 embedded
// documents so arrays/maps cannot hide an incomplete inspection. The seed
// also records a decoder failure at the boundary: serde_json can reject the
// next container before invoking our visitor.
const MAX_LITERAL_CONTAINERS: usize = 127;

struct LiteralSeed<'a, 't> {
    inspection: &'a mut TokenInspection<'t>,
    embedded_depth: usize,
    remaining_containers: usize,
    build: bool,
}

impl<'de> serde::de::DeserializeSeed<'de> for LiteralSeed<'_, '_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        let Self {
            inspection,
            embedded_depth,
            remaining_containers,
            build,
        } = self;
        let result = deserializer.deserialize_any(LiteralSeed {
            inspection: &mut *inspection,
            embedded_depth,
            remaining_containers,
            build,
        });
        if remaining_containers == 0 && result.is_err() {
            // Typed traversal provenance, not an error-message match. A
            // boundary failure cannot prove that every nested value was
            // inspected, even if an optional embedded parse is discarded.
            inspection.incomplete = true;
        }
        result
    }
}
impl<'de> serde::de::Visitor<'de> for LiteralSeed<'_, '_> {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a literal JSON value")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        let value = Value::from(v);
        self.inspection.scalar(&value);
        Ok(value)
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        let value = Value::from(v);
        self.inspection.scalar(&value);
        Ok(value)
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        let value = Value::from(v);
        self.inspection.scalar(&value);
        Ok(value)
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        self.inspection.inspect(v, self.embedded_depth, true);
        Ok(if self.build {
            Value::String(v.to_owned())
        } else {
            Value::Null
        })
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        self.inspection.inspect(&v, self.embedded_depth, true);
        Ok(if self.build {
            Value::String(v)
        } else {
            Value::Null
        })
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let Some(remaining_containers) = self.remaining_containers.checked_sub(1) else {
            self.inspection.incomplete = true;
            return Err(serde::de::Error::custom(
                "response container nesting exceeds safe inspection",
            ));
        };
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(LiteralSeed {
            inspection: &mut *self.inspection,
            embedded_depth: self.embedded_depth,
            remaining_containers,
            build: self.build,
        })? {
            if self.build {
                values.push(value);
            }
        }
        Ok(if self.build {
            Value::Array(values)
        } else {
            Value::Null
        })
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let Some(remaining_containers) = self.remaining_containers.checked_sub(1) else {
            self.inspection.incomplete = true;
            return Err(serde::de::Error::custom(
                "response container nesting exceeds safe inspection",
            ));
        };
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.inspection.inspect(&key, self.embedded_depth, false);
            let value = map.next_value_seed(LiteralSeed {
                inspection: &mut *self.inspection,
                embedded_depth: self.embedded_depth,
                remaining_containers,
                build: self.build,
            })?;
            if self.build {
                values.insert(key, value);
            }
        }
        Ok(if self.build {
            Value::Object(values)
        } else {
            Value::Null
        })
    }
}

fn literal_document(bytes: &[u8], inspection: &mut TokenInspection<'_>) -> Option<Value> {
    use serde::de::DeserializeSeed;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = (LiteralSeed {
        inspection,
        embedded_depth: 0,
        remaining_containers: MAX_LITERAL_CONTAINERS,
        build: true,
    })
    .deserialize(&mut decoder)
    .ok()?;
    decoder.end().ok()?;
    Some(value)
}

fn token_inspection(token: &str) -> TokenInspection<'_> {
    TokenInspection {
        token,
        authentication: None,
        scan_decoded: true,
        echo: false,
        incomplete: false,
    }
}

/// Does any JSON string literal of this body carry a guarded secret once
/// decoded? Duplicate members are all inspected: a parsed document keeps
/// only the last member, so the raw literals are the complete evidence.
/// A recovered literal is screened exactly like a parsed string: its decoded
/// text is checked, and a literal that is itself an embedded JSON document
/// goes through the same bounded `TokenInspection` recursion as the primary
/// parse. Double-escaping therefore cannot hide a bearer token, sign-on
/// credential or issued cookie value inside a raw-fallback body. Recursion
/// that exceeds the depth budget marks the response unreviewed (fail closed)
/// instead of exporting unscreened bytes.
fn decoded_strings_carry_secret(body: &[u8], inspection: &mut TokenInspection<'_>) -> bool {
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
        inspection.inspect(&literal, 0, true);
        if inspection.echo {
            return true;
        }
        index = next;
    }
    false
}

/// Decode the JSON string literal that starts at `start`. The second value is
/// the offset after the literal. A literal that never closes is refused.
/// Combine UTF-16 pairs without changing unpaired-surrogate or loose-escape
/// screening. The decoded credential material is zeroized on drop.
fn decode_json_string_literal(body: &[u8], start: usize) -> Option<(Zeroizing<String>, usize)> {
    let mut cursor = start + 1;
    let mut decoded = Zeroizing::new(String::new());
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
                        let code = read_escape_code(body, &mut cursor)?;
                        // A high surrogate is only half of a character. The low
                        // half must follow immediately; an unpaired surrogate
                        // keeps the replacement character.
                        let point = if (0xD800..=0xDBFF).contains(&code) {
                            match next_escape_code(body, cursor) {
                                Some(low) if (0xDC00..=0xDFFF).contains(&low) => {
                                    cursor += 6;
                                    Some(0x1_0000 + ((code - 0xD800) << 10) + (low - 0xDC00))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };
                        match point {
                            Some(point) => {
                                decoded.push(char::from_u32(point).expect("combined surrogate"))
                            }
                            None => decoded.push(char::from_u32(code).unwrap_or('\u{fffd}')),
                        }
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

/// Read the four hexadecimal digits of a `\uXXXX` escape and leave the cursor
/// after them.
fn read_escape_code(body: &[u8], cursor: &mut usize) -> Option<u32> {
    let mut code = 0u32;
    let mut digits = 0;
    while digits < 4 {
        let digit = *body.get(*cursor)?;
        let value = (digit as char).to_digit(16)?;
        code = code * 16 + value;
        *cursor += 1;
        digits += 1;
    }
    Some(code)
}

/// The code unit of an immediately following `\uXXXX` escape, if the literal
/// continues with one.
fn next_escape_code(body: &[u8], cursor: usize) -> Option<u32> {
    if body.get(cursor) != Some(&b'\\') || body.get(cursor + 1) != Some(&b'u') {
        return None;
    }
    let mut probe = cursor + 2;
    read_escape_code(body, &mut probe)
}

/// Facts about one response body that both the projection and the shared
/// governor settlement must agree on.
struct ResponseFacts {
    /// The body carries the supplied bearer token, verbatim, percent-encoded,
    /// or inside a decoded JSON string.
    token_echo: bool,
    content_type_echo: bool,
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
    analyze_authenticated_body(body, token, None)
}

fn analyze_authenticated_body(
    body: &[u8],
    token: &str,
    authentication: Option<Screening<'_>>,
) -> ResponseFacts {
    let mut facts = ResponseFacts {
        token_echo: false,
        content_type_echo: false,
        inspection_incomplete: false,
        session_denied: false,
        document: None,
    };
    // Always examine the original, even for a short token or non-JSON body.
    // Continue parsing after an echo so session denial remains an independent
    // fact for the original lease. Without escapes, decoded literals are
    // already covered by the original scan; nested parsing still runs.
    let mut inspection = token_inspection(token);
    inspection.authentication = authentication;
    let raw_echo = inspection.carries_secret(body);
    inspection.echo = raw_echo;
    inspection.scan_decoded =
        !raw_echo && (!token.is_empty() || authentication.is_some()) && body.contains(&b'\\');
    let document = literal_document(body, &mut inspection);
    // When the body is not one complete JSON document, recovered literals
    // are screened with the same bounded embedded-document recursion. An
    // echo observed before a parse failure is still real decoded evidence,
    // so it withholds the body even without a parsed document.
    let fallback_echo = document.is_none()
        && inspection.scan_decoded
        && decoded_strings_carry_secret(body, &mut inspection);
    facts.token_echo = raw_echo || inspection.echo || fallback_echo;
    facts.inspection_incomplete = inspection.incomplete;
    if let Some(document) = document {
        facts.session_denied = session_denied_document(&document);
        facts.document = Some(document);
    }
    facts
}

/// Screen one response body and its projected MIME with the caller's bearer
/// token, the invocation's accumulated issued-cookie guard and any sign-on
/// authentication material. Fresh and cached responses share this exact
/// analysis, so a cookie issued by an earlier page of the same invocation
/// also withholds a later fresh or cached body that echoes it, and a cached
/// `Content-Type` carrying such a value is never projected either.
fn screened_body_facts(
    response: &Response,
    token: &str,
    issued: &IssuedCookies,
    authentication: Option<Screening<'_>>,
) -> ResponseFacts {
    let contains =
        |bytes: &[u8]| issued.carries(bytes) || authentication.is_some_and(|screen| screen(bytes));
    let combined: Option<Screening<'_>> = if issued.is_empty() && authentication.is_none() {
        None
    } else {
        Some(&contains)
    };
    let mut facts = analyze_authenticated_body(&response.body, token, combined);
    facts.content_type_echo = combined.is_some_and(|contains| {
        response.headers.get("content-type").is_some_and(|value| {
            credential_value_carries_token(value, token)
                || contains(value.as_bytes())
                || contains(value.to_ascii_lowercase().as_bytes())
        })
    });
    facts.token_echo |= facts.content_type_echo;
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
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            id: u64,
            status: String,
            reply_count: u32,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            id: raw.id,
            status: raw.status,
            reply_count: raw.reply_count,
        })
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
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
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
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            token: raw.token,
            operation: raw.operation,
            token_source: raw.token_source,
            limit: raw.limit,
            page: raw.page,
            max_pages: raw.max_pages,
            since_id: raw.since_id,
            since_time: raw.since_time,
            known: raw.known,
            refresh: raw.refresh,
            download_attachments: raw.download_attachments,
        })
    }
}

struct DetailInput {
    token: Option<Zeroizing<String>>,
    operation: Option<Operation>,
    token_source: Option<TokenSource>,
    // Absent and null are both "no id supplied"; the caller never receives a
    // defaulted `0` request for a record it did not name.
    id: Option<u64>,
    refresh: Option<bool>,
    download_attachments: Option<bool>,
}
impl<'de> Deserialize<'de> for DetailInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default, deserialize_with = "deserialize_optional_secret")]
            token: Option<Zeroizing<String>>,
            operation: Option<Operation>,
            token_source: Option<TokenSource>,
            id: Option<u64>,
            refresh: Option<bool>,
            download_attachments: Option<bool>,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            token: raw.token,
            operation: raw.operation,
            token_source: raw.token_source,
            id: raw.id,
            refresh: raw.refresh,
            download_attachments: raw.download_attachments,
        })
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    List,
    Detail,
    Session,
}

struct SessionInput {
    operation: Option<Operation>,
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
            #[serde(default, deserialize_with = "deserialize_session_operation")]
            operation: Option<Operation>,
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
            operation: raw.operation,
            authorized: raw.authorized,
            username: raw.username,
            password: raw.password,
            intent: raw.intent,
            read: raw.read,
        })
    }
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn deserialize_session_operation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Operation>, D::Error> {
    Operation::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum SessionRead {
    List {
        enabled: bool,
        #[serde(default = "default_session_limit")]
        limit: u32,
        #[serde(default = "default_session_page")]
        page: u32,
    },
    Detail {
        enabled: bool,
        id: u64,
    },
}

fn default_session_limit() -> u32 {
    DEFAULT_LIMIT
}
fn default_session_page() -> u32 {
    1
}

// Ignored fields are consumed by serde's IgnoredAny path, not materialized
// into Value or copied into a serialized request. The second typed parse
// enforces the selected operation's complete deny_unknown_fields contract.
struct OperationSelector {
    operation: Operation,
}
impl<'de> Deserialize<'de> for OperationSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            operation: Operation,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            operation: raw.operation,
        })
    }
}

/// Enforce object shape before typed field decoding; Raw helpers, not the
/// outer types, are delegated through MapAccessDeserializer to avoid recursion.
fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
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
    if parsed
        .operation
        .is_some_and(|operation| operation != Operation::List)
    {
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
        return Err(invalid_input(
            "page is outside the supported pagination range",
        ));
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
    if parsed
        .operation
        .is_some_and(|operation| operation != Operation::Detail)
    {
        return Err(invalid_input("the ihome operation must be detail"));
    }
    let token = parsed.token.take().ok_or_else(token_required)?;
    if !valid_token(token.as_str()) {
        return Err(token_required());
    }
    if parsed.download_attachments == Some(true) {
        return Err(attachment_download_unsupported());
    }
    // The read is only ever for a record the caller named from the source.
    let id = source_appeal_id(parsed.id.ok_or_else(missing_appeal_id)?)?;
    Ok(DetailRequest {
        token,
        token_source: parsed.token_source,
        id,
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
    // Defence in depth for every caller, including the one-shot session read:
    // a placeholder id never becomes a request for a record it did not name.
    let id = source_appeal_id(id)?;
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
    let Some(id) = path.strip_prefix(IHOME_DETAIL_PREFIX) else {
        return false;
    };
    // Only the canonical decimal spelling of a positive source id is admitted,
    // so `0`, `007` or an out-of-range digit run can never address a detail.
    id.parse::<u64>()
        .is_ok_and(|value| value >= MIN_APPEAL_ID && value.to_string() == id)
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
        let directory =
            governor::open_directory(&base.join(scope), true, true).map_err(|_| cache_error())?;
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
            || cached
                .headers
                .iter()
                .any(|(name, value)| !HEADER_NAMES.contains(&name.as_str()) || !valid_header(value))
        {
            return Err(corrupt_cache());
        }
        let body = STANDARD
            .decode(&cached.body_base64)
            .map_err(|_| corrupt_cache())?;
        if body.len() > MAX_BODY || sha256(&body) != cached.sha256 {
            return Err(corrupt_cache());
        }
        let body_assessment = assess_response_body(
            &body,
            cached.headers.get("content-type").map(String::as_str),
            true,
        );
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
                return Err(Error::new(
                    "safety_latched",
                    "a retained safety observation prevents this result",
                ));
            }
            return Err(Error::new(
                "cached_response_unreviewed",
                "retained response predates cookie admission; original preserved and body withheld",
            ));
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
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), target.as_ptr(), 0) } != 0
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
        issued: &mut IssuedCookies,
        process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if refresh && !online {
            return Err(invalid_input("refresh requires online authorization"));
        }
        if !refresh {
            if let Some((response, challenge)) = self.load(url)? {
                // A cached body is screened with the whole invocation's
                // accumulated cookie guard, not just this page's headers.
                let facts = screened_body_facts(&response, token, issued, None);
                if facts.token_echo {
                    // A cached body that echoes the submitted token or any
                    // credential issued during this invocation is never
                    // published and never kept on disk.
                    self.remove(url)?;
                }
                if cached_rejection(&response, &challenge, &facts) {
                    // A cached HTTP authentication rejection and a cached
                    // application-level refusal must never be replayed as an
                    // ordinary result.
                    return Err(Error::new(
                        "safety_latched",
                        "a retained safety observation prevents this result",
                    ));
                }
                if facts.inspection_incomplete {
                    return Err(Error::new(
                        "response_unreviewed",
                        "response content withheld because token inspection was incomplete",
                    ));
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
        Transport::open()?.fetch(self, url, token, refresh, issued, process)
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
        Ok(Self {
            governor,
            http: Self::client()?,
        })
    }

    /// Unit-process fixture transport bound to an isolated governor directory.
    /// No request is sent unless the bounded cache misses.
    #[cfg(test)]
    fn open_isolated(governor: Governor) -> Result<Self, Error> {
        Ok(Self {
            governor,
            http: Self::client()?,
        })
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
            .map_err(|_| {
                Error::new(
                    "transport_unavailable",
                    "cannot initialize the ihome transport",
                )
            })?;
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
        issued: &mut IssuedCookies,
        process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let request = read_request(&self.http, url, token)?;
        let lease = net::acquire(&self.governor)?;
        if !refresh {
            match cache.load(url) {
                Ok(Some((response, challenge))) => {
                    let facts = screened_body_facts(&response, token, issued, None);
                    if facts.token_echo {
                        // A cached body that echoes the submitted token or an
                        // invocation-issued cookie is never published and
                        // never kept on disk.
                        cache.remove(url).map_err(|_| governor_error())?;
                    }
                    // The cached hit carries the request to completion with no
                    // network access; settle the lease without a request.
                    lease
                        .finish_without_request()
                        .map_err(|_| governor_error())?;
                    if facts.inspection_incomplete {
                        return Err(Error::new(
                            "response_unreviewed",
                            "response content withheld because token inspection was incomplete",
                        ));
                    }
                    return process(&response, &challenge, &facts);
                }
                Ok(None) => {}
                Err(error) => {
                    lease
                        .finish_without_request()
                        .map_err(|_| governor_error())?;
                    return Err(error);
                }
            }
        }
        execute_read(
            request,
            url,
            token,
            lease,
            None,
            issued,
            |response, challenge, facts, issues_cookie| {
                admit_response(cache, response, challenge, facts, issues_cookie, process)
            },
        )
    }
}

fn read_request(
    client: &Client,
    url: &Url,
    token: &str,
) -> Result<reqwest::blocking::RequestBuilder, Error> {
    if !allowed_url(url) {
        return Err(invalid_url());
    }
    let credential = Zeroizing::new(format!("Bearer {token}"));
    let mut authorization = reqwest::header::HeaderValue::from_bytes(credential.as_bytes())
        .map_err(|_| invalid_input("the bearer token cannot be sent as a header"))?;
    authorization.set_sensitive(true);
    Ok(client
        .get(url.clone())
        .header("Accept-Encoding", "identity")
        .header("Accept", "application/json")
        .header("Referer", IHOME_REFERER)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .timeout(Duration::from_secs(45)))
}

/// The credential values issued by `Set-Cookie` headers during one complete
/// public list/detail/session invocation. `collect_headers` does not retain
/// `Set-Cookie`, and this reader maintains no cookie jar: an issued value is
/// never persisted or transmitted, but an echo of it inside any later response
/// of the same invocation is still a credential disclosure. The guard is
/// created once per invocation, accumulates every fresh response's values
/// without resetting or evicting between pages, and also screens cached
/// bodies and their projected MIME. Because a page only learns the values
/// issued *before* it, the consumer envelope is screened once more after the
/// traversal settles, against this complete history: a value first issued by
/// a later page withholds every earlier record that already carried it, and a
/// cached admission whose retained content matches is removed. The guard is
/// zeroized with the invocation.
#[derive(Default)]
struct IssuedCookies {
    /// Every nonempty first-pair value, stored exactly as the server sent
    /// it, quotes included. Matching also covers the unquoted spelling.
    values: Vec<Zeroizing<String>>,
    bytes: usize,
}

/// One invocation may accumulate only so much credential material before it
/// can no longer review it; exceeding the guard refuses the response rather
/// than screening a subset or forgetting an earlier page's credential.
const MAX_ISSUED_COOKIE_VALUES: usize = 64;
const MAX_ISSUED_COOKIE_BYTES: usize = 64 * 1024;

/// A cookie value that cannot be reviewed cannot be screened. Refuse the
/// whole response rather than guess which spelling upstream will echo.
fn issued_cookie_refusal() -> Error {
    Error::new(
        "invalid_headers",
        "the ihome response issued a cookie that cannot be reviewed",
    )
}

impl IssuedCookies {
    /// Review one response's `Set-Cookie` values while the raw header map is
    /// still available, before `collect_headers` discards it, and retain them
    /// for the rest of the invocation. Only the first `name=value` pair is
    /// credential material; attributes are not screened. A header that
    /// cannot be parsed on its own terms (a missing name, a missing `=`, a
    /// control byte, or ambiguous quoting) refuses the response. An empty
    /// value is a deletion, not a transmitting secret, so it is not retained.
    fn absorb(&mut self, headers: &reqwest::header::HeaderMap) -> Result<(), Error> {
        for value in headers.get_all(reqwest::header::SET_COOKIE) {
            let text = value.to_str().map_err(|_| issued_cookie_refusal())?;
            let Some(pair) = text.split(';').next() else {
                return Err(issued_cookie_refusal());
            };
            let Some((name, value)) = pair.split_once('=') else {
                return Err(issued_cookie_refusal());
            };
            let name = name.trim();
            let value = value.trim();
            // Use the same cookie-name grammar as the authentication jar.
            // Invalid names or folded first pairs cannot establish which
            // value must remain private, so they refuse instead of guessing.
            if name.is_empty()
                || name.len() > 256
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            {
                return Err(issued_cookie_refusal());
            }
            // A quoted value must parse on its own terms: either both DQUOTEs
            // wrap it or neither does, and the unquoted spelling never
            // carries a bare quote.
            let unquoted = if value.starts_with('"') || value.ends_with('"') {
                value
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'))
                    .ok_or_else(issued_cookie_refusal)?
            } else {
                value
            };
            // RFC cookie-octets, also used by the authentication jar: quotes
            // only delimit the whole value. Spaces, backslashes and commas
            // inside it are malformed or ambiguous, not values to skip.
            if !unquoted.bytes().all(|byte| {
                matches!(byte,
                0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
            }) {
                return Err(issued_cookie_refusal());
            }
            if unquoted.is_empty() {
                // `name=` or `name=""`: upstream is deleting this cookie, so
                // there is no transmitting secret to screen.
                continue;
            }
            // The bounds are cumulative across the whole invocation: the
            // guard never resets or evicts an earlier page's secret.
            if self.values.len() >= MAX_ISSUED_COOKIE_VALUES
                || self.bytes.saturating_add(value.len()) > MAX_ISSUED_COOKIE_BYTES
            {
                return Err(issued_cookie_refusal());
            }
            self.bytes += value.len();
            self.values.push(Zeroizing::new(value.to_string()));
        }
        Ok(())
    }

    /// A standalone guard for one header map, used by focused tests.
    #[cfg(test)]
    fn review(headers: &reqwest::header::HeaderMap) -> Result<Self, Error> {
        let mut issued = IssuedCookies::default();
        issued.absorb(headers)?;
        Ok(issued)
    }

    fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Whether `bytes` echoes any issued credential value, in any of the
    /// reversible spellings the token guard already supports. Both the raw
    /// value and its unquoted spelling are credential carriers.
    fn carries(&self, bytes: &[u8]) -> bool {
        self.values.iter().any(|value| {
            net::carries_secret(bytes, value)
                || value
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'))
                    .is_some_and(|unquoted| net::carries_secret(bytes, unquoted))
        })
    }
}

/// The existing response/body admission and settlement, shared by a legacy
/// token read and a one-shot session. The latter passes its original auth
/// lease and retains all authentication guards until processing completes.
fn execute_read<T>(
    request: reqwest::blocking::RequestBuilder,
    url: &Url,
    token: &str,
    mut lease: governor::RequestLease<'_>,
    authentication: Option<Screening<'_>>,
    issued: &mut IssuedCookies,
    process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts, bool) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut raw = match lease.start_request(|| request.send()) {
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
    observe_response_headers(&mut lease, status, raw.headers(), header_challenge)?;
    let mut challenge = if header_challenge {
        ChallengeAssessment::Detected
    } else {
        ChallengeAssessment::Unreviewed
    };
    let mut facts = ResponseFacts {
        token_echo: false,
        content_type_echo: false,
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
        // Absorb the cookies this response issues into the invocation's
        // guard before `collect_headers` discards their values. A response
        // that cannot be reviewed is refused outright; a reviewable one
        // extends the guard so an echo of a newly issued value is withheld
        // like the bearer token, on this and every later page.
        // Keep an admission failure pending until the original body has
        // supplied its independent challenge/session-denial facts. The
        // refusal still precedes all projection and cache writes.
        let cookie_review = issued.absorb(raw.headers());
        let headers = collect_headers(raw.headers())?;
        let mut body = Vec::new();
        let read = raw
            .by_ref()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut body);
        let assessment = assess_response_body(
            &body,
            headers.get("content-type").map(String::as_str),
            read.is_ok() && body.len() <= MAX_BODY,
        );
        challenge = if header_challenge {
            ChallengeAssessment::Detected
        } else {
            assessment
        };
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
        // One combined guard screens the body once: the caller's bearer
        // token, the sign-on authentication material, and every cookie
        // value issued so far in this invocation. A newly issued value is
        // session material, so its echo is a credential echo even when
        // the response carries no other credential.
        facts = screened_body_facts(&response, token, issued, authentication);
        cookie_review?;
        process(&response, &challenge, &facts, issues_session_cookie)
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
    lease.finish(outcome).map_err(|_| governor_error())?;
    result
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
    let processed = admit_body(response, challenge, facts, process)?;
    // A response that carried a session cookie is never written to the
    // replayable cache: the cookie is session material. The business entries
    // it carries are still projected, because they are read through the
    // caller's bearer token and are screened for credential echoes below.
    if !facts.token_echo && !issues_session_cookie {
        cache.save(response, challenge)?;
    }
    Ok(processed)
}

fn admit_body<T>(
    response: &Response,
    challenge: &ChallengeAssessment,
    facts: &ResponseFacts,
    process: impl FnOnce(&Response, &ChallengeAssessment, &ResponseFacts) -> Result<T, Error>,
) -> Result<T, Error> {
    if facts.inspection_incomplete {
        return Err(Error::new(
            "response_unreviewed",
            "response content withheld because token inspection was incomplete",
        ));
    }
    process(response, challenge, facts)
}

fn observe_response_headers(
    lease: &mut governor::RequestLease<'_>,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    challenge: bool,
) -> Result<(), Error> {
    lease
        .observe_http_many(
            status,
            headers
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            challenge,
        )
        .map_err(|_| governor_error())
}

fn collect_headers(
    headers: &reqwest::header::HeaderMap,
) -> Result<BTreeMap<String, String>, Error> {
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
        total = total.checked_add(name.len() + value.len()).ok_or_else(|| {
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
fn assess_response_body(bytes: &[u8], mime: Option<&str>, complete: bool) -> ChallengeAssessment {
    if mime.is_some_and(|value| value.contains(',')) {
        return match assess_challenge_body(bytes, None, complete) {
            ChallengeAssessment::Detected => ChallengeAssessment::Detected,
            _ => ChallengeAssessment::Unreviewed,
        };
    }
    assess_challenge_body(bytes, mime, complete)
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
    let token = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                    )
            })
    };
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
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect();
    [
        "password",
        "passwd",
        "token",
        "cookie",
        "authorization",
        "secret",
        "session",
        "ticket",
        "execution",
        "credential",
        "csrf",
        "jwt",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn credential_url(url: &Url) -> bool {
    !url.username().is_empty()
        || url.password().is_some()
        || url.query_pairs().any(|(key, _)| credential_key(&key))
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
    while let Some(position) = cursor
        .windows(7)
        .position(|window| window.eq_ignore_ascii_case(b"bearer "))
    {
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
struct JsonSafetySeed {
    depth: usize,
}
impl<'de> serde::de::DeserializeSeed<'de> for JsonSafetySeed {
    type Value = bool;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        if self.depth > 32 {
            return Err(serde::de::Error::custom(
                "response nesting exceeds safe inspection",
            ));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for JsonSafetySeed {
    type Value = bool;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON response value")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<bool, E> {
        Ok(false)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<bool, E> {
        let text = value.trim();
        if text.starts_with(['{', '[']) {
            return Ok(json_contains_credentials(text.as_bytes(), self.depth + 1));
        }
        // A JSON string can itself be another complete JSON document. Recurse
        // under the same depth budget so escaping cannot hide credential keys.
        if text.starts_with('"') {
            return Ok(json_contains_credentials(text.as_bytes(), self.depth + 1));
        }
        Ok(credential_reference(text))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        let mut unsafe_value = false;
        while let Some(nested) = seq.next_element_seed(JsonSafetySeed {
            depth: self.depth + 1,
        })? {
            unsafe_value |= nested;
        }
        Ok(unsafe_value)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut unsafe_value = false;
        while let Some(key) = map.next_key::<String>()? {
            unsafe_value |= credential_key(&key);
            unsafe_value |= map.next_value_seed(JsonSafetySeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(unsafe_value)
    }
}
fn json_contains_credentials(bytes: &[u8], depth: usize) -> bool {
    use serde::de::DeserializeSeed;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    match (JsonSafetySeed { depth }).deserialize(&mut decoder) {
        Ok(unsafe_value) => unsafe_value || decoder.end().is_err(),
        Err(_) => true,
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
    BusinessRejected,
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
            Self::BusinessRejected => "business_rejected",
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

fn response_refusal(
    response: &Response,
    challenge: &ChallengeAssessment,
) -> Option<FallbackReason> {
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
    if response
        .headers
        .get("content-encoding")
        .is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity"))
    {
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
        || mime
            .as_bytes()
            .get(mime.len().saturating_sub(5)..)
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
    title: Option<String>,
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
    Ok((required_u64(map, "id")?, required_str(map, "name")?))
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
                if let Some(decoded) =
                    literal_document(trimmed.as_bytes(), &mut token_inspection(""))
                {
                    collect_declared_urls(&decoded, out, depth + 1);
                    return;
                }
            }
            let Ok(url) = Url::parse(trimmed) else {
                return;
            };
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || credential_url(&url)
            {
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
        title: match map.get("title") {
            None => None,
            Some(Value::String(title)) => Some(title.clone()),
            Some(_) => return Err(FallbackReason::UpstreamShape),
        },
        content,
        created_at: required_str(map, "created_at")?,
        status: required_str(map, "publish_status_text")?,
        replies,
        departments,
        attachments,
    })
}

/// Require the source-declared positive business envelope, independently of
/// HTTP status. Authentication/challenge facts have already been inspected.
fn envelope_data<'a>(
    mime: Option<&str>,
    document: Option<&'a Value>,
) -> Result<&'a Map<String, Value>, FallbackReason> {
    if let Some(mime) = mime {
        if !json_mime(mime) {
            return Err(FallbackReason::UnexpectedContent);
        }
    }
    let document = document.ok_or(FallbackReason::UpstreamParse)?;
    let root = document.as_object().ok_or(FallbackReason::UpstreamShape)?;
    if required_u64(root, "code")? != 20000 {
        return Err(FallbackReason::BusinessRejected);
    }
    match root.get("success") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) => return Err(FallbackReason::BusinessRejected),
        _ => return Err(FallbackReason::UpstreamShape),
    }
    root.get("data")
        .and_then(Value::as_object)
        .ok_or(FallbackReason::UpstreamShape)
}

#[derive(Clone, Copy)]
struct Pagination {
    current_page: u32,
    last_page: u32,
    total: u64,
}

impl Pagination {
    fn parse(data: &Map<String, Value>) -> Option<Self> {
        Some(Self {
            current_page: u32::try_from(data.get("current_page")?.as_u64()?).ok()?,
            last_page: u32::try_from(data.get("last_page")?.as_u64()?).ok()?,
            total: data.get("total")?.as_u64()?,
        })
    }
}

/// Decode once in the caller; missing pagination does not invent or discard
/// otherwise valid records, but cannot authorize traversal or a cursor.
fn parse_envelope(
    mime: Option<&str>,
    document: Option<&Value>,
) -> Result<(Option<Pagination>, Vec<Entry>), FallbackReason> {
    let data = envelope_data(mime, document)?;
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
    Ok((Pagination::parse(data), entries))
}

/// Accept the documented single item as `data` or as `data.data`.
fn parse_detail_envelope(
    mime: Option<&str>,
    document: Option<&Value>,
) -> Result<Option<Entry>, FallbackReason> {
    let data = envelope_data(mime, document)?;
    let item = match data.get("data") {
        Some(Value::Array(items)) if items.len() == 1 => &items[0],
        Some(Value::Array(items)) if items.is_empty() => return Ok(None),
        Some(value @ Value::Object(_)) => value,
        None if data.contains_key("id") => document
            .and_then(|root| root.get("data"))
            .ok_or(FallbackReason::UpstreamShape)?,
        _ => return Err(FallbackReason::UpstreamShape),
    };
    Ok(Some(parse_entry(item)?))
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

fn reply_summary(reply: &Reply) -> Value {
    let preview: String = reply
        .content
        .chars()
        .take(MAX_REPLY_PREVIEW_CHARS)
        .collect();
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
    let mut projected = json!({
        "id": entry.id,
        "content": entry.content,
        "created_at": entry.created_at,
        "status": entry.status,
        "reply_count": entry.replies.len(),
        "replies": entry.replies.iter().map(reply_summary).collect::<Vec<Value>>(),
        "departments": entry.departments.iter().map(|(id, name)| json!({"id": id, "name": name})).collect::<Vec<Value>>(),
        "attachments": attachments,
        "provenance": entry_provenance(response),
    });
    if let Some(title) = &entry.title {
        projected["title"] = json!(title);
    }
    projected
}

/// The degradation evidence: the original bytes when they are admissible, the
/// content type that was actually observed (`null` when the upstream sent
/// none, when the value carries the submitted credential, or when it is not a
/// well-formed MIME type), the byte length, the SHA-256 of the body and the
/// reason the structure could not be built.
fn evidence(reason: FallbackReason, response: &Response, token: &str) -> Value {
    let leading = response.body.trim_ascii_start();
    let json_source = response
        .headers
        .get("content-type")
        .is_some_and(|mime| json_mime(mime))
        || leading.starts_with(b"{")
        || leading.starts_with(b"[")
        || leading.starts_with(b"\"");
    let credential_json = json_source && json_contains_credentials(&response.body, 0);
    let credential_bearer = bearer_credential_present(&response.body);
    let credential_form = std::str::from_utf8(&response.body)
        .ok()
        .is_some_and(|source| {
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

/// The response facts one page retains until the consumer envelope is
/// published. The complete issued-cookie history is only known after the
/// traversal settles, so publication re-screens these facts before they are
/// released or their cached admission is trusted. The retained body is the
/// source material that produced every projection this page published; it is
/// kept exactly once per consumed page, bounded by `MAX_BODY`, because only
/// the original bytes admit the complete re-screen a later cookie issue
/// requires, including literals that survive only in escaped form. Generated
/// adapter vocabulary such as envelope field names is never screened.
struct PageSource {
    url: String,
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    sha256: String,
    fetched_at_unix_ms: u64,
    cache_status: CacheStatus,
}

/// Retain the facts of the response that produced one outcome.
fn page_source(response: &Response) -> PageSource {
    PageSource {
        url: response.url.clone(),
        status: response.status,
        headers: response.headers.clone(),
        body: response.body.clone(),
        sha256: response.sha256.clone(),
        fetched_at_unix_ms: response.fetched_at_unix_ms,
        cache_status: response.cache_status,
    }
}

/// A response view of the retained facts, used only to rebuild a withheld
/// page's metadata and evidence. The original body supplies the evidence's
/// byte count, but `evidence` never exports raw bytes for `CredentialEcho`.
impl PageSource {
    fn withheld_view(&self) -> Response {
        Response {
            url: self.url.clone(),
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
            sha256: self.sha256.clone(),
            fetched_at_unix_ms: self.fetched_at_unix_ms,
            cache_status: self.cache_status,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }
}

struct PageOutcome {
    meta: Value,
    success: Option<bool>,
    evidence: Option<Value>,
    entries: Vec<Value>,
    pagination: Option<Pagination>,
    source: PageSource,
}

fn refused_page(
    response: &Response,
    token: &str,
    reason: FallbackReason,
    success: Option<bool>,
) -> PageOutcome {
    PageOutcome {
        meta: page_meta(response, 0, token),
        success,
        evidence: Some(evidence(reason, response, token)),
        entries: Vec::new(),
        pagination: None,
        source: page_source(response),
    }
}

fn credential_echo_page(response: &Response, token: &str, content_type_echo: bool) -> PageOutcome {
    let mut page = refused_page(response, token, FallbackReason::CredentialEcho, None);
    if content_type_echo {
        page.meta["content_type"] = Value::Null;
        page.meta["content_type_parameters_withheld"] = json!(true);
        if let Some(evidence) = &mut page.evidence {
            evidence["content_type"] = Value::Null;
            evidence["content_type_parameters_withheld"] = json!(true);
        }
    }
    page
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

fn pagination_issue(
    pagination: Option<Pagination>,
    page: u32,
    limit: u32,
    count: usize,
) -> Option<&'static str> {
    let Some(pagination) = pagination else {
        return Some("pagination_unconfirmed");
    };
    if pagination.current_page != page {
        return Some("page_mismatch");
    }
    let last = if pagination.total == 0 {
        1
    } else {
        (pagination.total - 1) / u64::from(limit) + 1
    };
    let preceding = u64::from(page - 1) * u64::from(limit);
    let expected = pagination
        .total
        .saturating_sub(preceding)
        .min(u64::from(limit));
    if pagination.current_page == 0
        || pagination.current_page > pagination.last_page
        || u64::from(pagination.last_page) != last
        || u64::try_from(count).ok() != Some(expected)
    {
        return Some("pagination_inconsistent");
    }
    None
}

fn advisory() -> Value {
    json!({
        "upstream_idle_window": null,
        "inside_idle_window": null,
        "enforced": false,
        "note": "the current upstream idle window is unverified; this adapter never blocks, delays or retries because of an assumed window",
    })
}

fn attachments_notice() -> Value {
    json!({
        "downloaded": false,
        "contract": "unknown",
        "note": "only recognized source-declared URLs are listed, not a complete attachment inventory; no modern download contract is reviewed, legacy php-ihome routes are not evidence about this service, and no URL is guessed or fetched",
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
fn classify(request: &ListRequest, entry: &mut Value, counts: &mut Counts) -> Option<&'static str> {
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
    set_field(
        entry,
        "created_at_comparable",
        json!(parse_timestamp(&created_at).is_some()),
    );
    Some(change)
}

fn set_field(value: &mut Value, key: &str, field: Value) {
    if let Some(map) = value.as_object_mut() {
        map.insert(key.to_owned(), field);
    }
}

/// One settled traversal: every page the lazy acquisition read before its
/// first refusal, degradation, inconsistency or declared terminal page, plus
/// the observed pagination facts. Acquisition stops exactly where the single
/// pass used to stop; publication decisions are left to the caller.
struct ConsumedTraversal {
    outcomes: Vec<PageOutcome>,
    /// The pagination/duplicate/acquisition refusal the traversal settled
    /// with; `None` when the read window was internally consistent.
    incomplete: Option<&'static str>,
    has_more: bool,
    reached_terminal: bool,
}

/// Consume the lazy page acquisition exactly as far as the original envelope
/// fold would have. No page is projected further than this point, so the
/// caller may re-screen every retained record against the *complete*
/// invocation issued-cookie history before publishing.
fn collect_traversal(
    request: &ListRequest,
    pages: impl IntoIterator<Item = Result<PageOutcome, Error>>,
) -> Result<ConsumedTraversal, Error> {
    let mut outcomes: Vec<PageOutcome> = Vec::new();
    let mut incomplete = None;
    let mut previous_pagination: Option<Pagination> = None;
    let mut has_more = false;
    let mut reached_terminal = false;
    let mut seen_ids = BTreeSet::new();

    for result in pages {
        let page = match result {
            Ok(page) => page,
            Err(error) if outcomes.is_empty() => return Err(error),
            Err(error) => {
                incomplete = Some(error.code);
                break;
            }
        };
        let expected_page = request.page + u32::try_from(outcomes.len()).unwrap_or(0);
        outcomes.push(page);
        let page = outcomes.last().expect("the outcome was just pushed");
        if page.evidence.is_some() {
            break;
        }
        incomplete = pagination_issue(
            page.pagination,
            expected_page,
            request.limit,
            page.entries.len(),
        );
        if incomplete.is_none()
            && previous_pagination
                .zip(page.pagination)
                .is_some_and(|(before, after)| {
                    before.total != after.total || before.last_page != after.last_page
                })
        {
            incomplete = Some("pagination_changed");
        }
        for entry in &page.entries {
            if let Some(id) = entry.get("id").and_then(Value::as_u64)
                && !seen_ids.insert(id)
            {
                incomplete.get_or_insert("duplicate_entry_id");
            }
        }
        if incomplete.is_some() {
            break;
        }
        if let Some(pagination) = page.pagination {
            has_more = pagination.current_page < pagination.last_page;
            reached_terminal = !has_more;
            previous_pagination = Some(pagination);
        }
        if reached_terminal {
            break;
        }
    }

    Ok(ConsumedTraversal {
        outcomes,
        incomplete,
        has_more,
        reached_terminal,
    })
}

/// Re-screen retained body bytes exactly like `analyze_authenticated_body`
/// does, but only against the issued-cookie guard: the raw bytes, every
/// decoded JSON literal and any embedded document. An unreviewable body
/// counts as carrying rather than exposing an unscreened spelling.
fn retained_bytes_carry_issued(bytes: &[u8], issued: &IssuedCookies) -> bool {
    if issued.is_empty() || bytes.is_empty() {
        return false;
    }
    if issued.carries(bytes) {
        return true;
    }
    let contains = |part: &[u8]| issued.carries(part);
    let mut inspection = token_inspection("");
    inspection.authentication = Some(&contains);
    inspection.scan_decoded = bytes.contains(&b'\\');
    let document = literal_document(bytes, &mut inspection);
    inspection.echo
        || (document.is_none()
            && inspection.scan_decoded
            && decoded_strings_carry_secret(bytes, &mut inspection))
        || inspection.incomplete
}

/// Does anything this page retained carry a value issued later in the same
/// invocation? Only *source* material is screened: the request URL, the
/// retained headers and the original body whose bytes produced every
/// projection this page published, including the reversible raw-evidence
/// channel. Adapter-generated envelope vocabulary — field names, labels and
/// provenance fields — is never credential evidence: an innocuous value that
/// collides with a generated key like `content_type` must not withhold a
/// safe page or strip required members.
fn page_carries_issued(page: &PageOutcome, issued: &IssuedCookies) -> bool {
    if issued.is_empty() {
        return false;
    }
    issued.carries(page.source.url.as_bytes())
        || page
            .source
            .headers
            .values()
            .any(|value| issued.carries(value.as_bytes()))
        || retained_bytes_carry_issued(&page.source.body, issued)
}

/// The documented constant a withheld page reports as its request URL when
/// the real URL itself carries an invocation-issued credential value. The
/// marker is a string so `page_meta_schema`'s required `url` member still
/// validates, and `url_withheld` states that the substitution happened.
/// A real-looking replacement URL is never fabricated.
const WITHHELD_URL_MARKER: &str = "withheld";

/// Publish one settled traversal. Every page is first re-screened against the
/// complete invocation issued-cookie history: a value first issued by a later
/// page is credential material wherever an earlier retained record carries
/// it, so that page's records are withheld as `credential_echo` degradation,
/// the traversal is never reported complete, and `purge` is asked to drop any
/// cache admission that would still serve credential-matching content.
fn publish_list_envelope(
    request: &ListRequest,
    issued: &IssuedCookies,
    mut purge: impl FnMut(&Url, &IssuedCookies) -> Result<(), Error>,
    traversal: ConsumedTraversal,
) -> Result<Value, Error> {
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
    let mut page_records: Vec<Value> = Vec::new();
    let mut degraded_evidence: Option<Value> = None;

    for page in traversal.outcomes {
        // A cached admission written before the complete history was known is
        // re-screened before publication: credential-matching content is never
        // preserved for replay. This applies to every consumed page, whether
        // or not the material it retained is itself withheld below.
        if let Ok(url) = Url::parse(&page.source.url) {
            purge(&url, issued)?;
        }
        let outcome = if page_carries_issued(&page, issued) {
            // A value issued by a later page makes everything this page
            // retained a credential disclosure. Publish exactly what a page
            // refused at read time would have published: provenance metadata
            // and evidence with no raw bytes. Only upstream-derived members
            // can carry the value: a carrying request URL is replaced by the
            // documented withheld marker, and a carrying Content-Type takes
            // the content_type_echo path; generated envelope vocabulary is
            // never touched.
            let content_type_echo = page
                .source
                .headers
                .get("content-type")
                .is_some_and(|value| issued.carries(value.as_bytes()));
            let view = page.source.withheld_view();
            let mut withheld =
                credential_echo_page(&view, request.token.as_str(), content_type_echo);
            if issued.carries(page.source.url.as_bytes()) {
                // The request URL itself is credential-bearing: the required
                // `url` member stays a string (the documented marker) and the
                // `url_withheld` flag states the substitution. The real URL
                // never reaches the envelope.
                withheld.meta["url"] = json!(WITHHELD_URL_MARKER);
                withheld.meta["url_withheld"] = json!(true);
            }
            withheld
        } else {
            page
        };
        let mut meta = outcome.meta;
        if let Some(pagination) = outcome.pagination {
            meta["pagination"] = json!({
                "current_page": pagination.current_page,
                "last_page": pagination.last_page,
                "total": pagination.total,
            });
        }
        page_records.push(meta);
        if let Some(success) = outcome.success {
            upstream_success = Some(success);
        }
        if let Some(found) = outcome.evidence {
            if degraded_evidence.is_none() {
                degraded_evidence = Some(found);
            }
            continue;
        }
        for mut entry in outcome.entries {
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
                                .and_then(|previous| compare_timestamps(&candidate, &previous))
                            {
                                Some(ordering) => ordering == Ordering::Greater,
                                None => {
                                    incomparable_dates = true;
                                    false
                                }
                            },
                            None => true,
                        },
                        None => {
                            incomparable_dates = true;
                            false
                        }
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

    let incomplete = traversal.incomplete;
    if incomparable_dates {
        max_created_at = None;
    }
    let pages_fetched = page_records.len();
    let next_page = request
        .page
        .saturating_add(u32::try_from(pages_fetched).unwrap_or(0));
    let complete = degraded_evidence.is_none() && traversal.reached_terminal;
    let provenance = match page_records.last().and_then(Value::as_object) {
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
            "next_page": if traversal.has_more { json!(next_page) } else { Value::Null },
            "has_more": traversal.has_more,
        })
    };
    Ok(json!({
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
    }))
}

/// Standalone publication for already-built outcomes, used by the session
/// read and by unit fixtures. No invocation cookie history reaches this
/// entry point beyond what each outcome's own read already screened, and no
/// cache admission is associated with the pages, so publication is a direct
/// fold of the consumed traversal.
fn build_list_envelope(
    request: &ListRequest,
    pages: impl IntoIterator<Item = Result<PageOutcome, Error>>,
) -> Result<Value, Error> {
    let traversal = collect_traversal(request, pages)?;
    let issued = IssuedCookies::default();
    publish_list_envelope(request, &issued, |_, _| Ok(()), traversal)
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
        Operation::Session => session(input, online),
    }
}

/// One explicit CAS attempt followed by one listing page or one detail.
/// Authentication material and response bytes never enter the response cache.
pub fn session(input: &str, online: bool) -> Result<Value, Error> {
    session_with_network(input, online, || {
        Ok((
            cas::http_client()?,
            Governor::open().map_err(|_| governor_error())?,
        ))
    })
}

pub(crate) fn session_with_network(
    input: &str,
    online: bool,
    network: impl FnOnce() -> Result<(Client, Governor), Error>,
) -> Result<Value, Error> {
    if input.len() > 65536 {
        return Err(invalid_input("the ihome session request is too large"));
    }
    let input: SessionInput = serde_json::from_str(input)
        .map_err(|_| invalid_input("the ihome session request is invalid"))?;
    if input
        .operation
        .is_some_and(|operation| operation != Operation::Session)
    {
        return Err(invalid_input("the ihome operation must be session"));
    }
    let (enabled, url) = match &input.read {
        SessionRead::List {
            enabled,
            limit,
            page,
        } => {
            if !(1..=MAX_LIMIT).contains(limit) || !(1..=MAX_PAGE).contains(page) {
                return Err(invalid_input(
                    "the ihome list limit or page is outside its supported range",
                ));
            }
            (*enabled, list_url(*limit, *page)?)
        }
        SessionRead::Detail { enabled, id } => (*enabled, detail_url(*id)?),
    };
    if !enabled {
        return Ok(
            json!({"schema_version":1,"type":"ihome_session","result":"disabled",
            "network_performed":false,"write_operations_performed":false}),
        );
    }
    if !input.authorized {
        return Err(Error::new(
            "permission",
            "explicit authorization for one ihome authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if *input.intent != format!("LOGIN {} ihome", &*input.username) {
        return Err(invalid_input(
            "the ihome authentication intent does not match",
        ));
    }
    if !online {
        return Err(Error::new(
            "online_required",
            "ihome sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let (client, governor) = network()?;
    let mut lease = net::acquire_kind(&governor, governor::RequestKind::Authentication)?;
    let prepared = cas::authenticate_service(&mut lease, &client, CasService::Ihome, credentials)
        .and_then(|mut session| {
            let token = session.take_service_credential()?;
            if !valid_token(&token) {
                return Err(Error::new(
                    "authentication_unconfirmed",
                    "the ihome handoff did not supply an admissible bearer token; no read was sent",
                ));
            }
            let request = read_request(&client, &url, &token)?;
            let reservation = lease.reserve_followup().map_err(|_| governor_error())?;
            if !reservation.cooldown_wait.is_zero() {
                return Err(Error::new(
                    "cooldown",
                    "the ihome read was deferred; no retry was performed",
                ));
            }
            if !reservation.request_wait.is_zero() {
                std::thread::sleep(reservation.request_wait);
            }
            Ok((session, token, request))
        });
    let (session, token, request) = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            if matches!(
                failure.code,
                "governor_denied" | "governor_error" | "governor_unavailable"
            ) {
                // Persistence uncertainty retains the original pending attempt.
                return Err(failure);
            }
            match failure.code {
                "auth_latched" => lease.finish(Outcome::CredentialRejected),
                "challenge_requires_human" => lease.finish(Outcome::CaptchaRequired),
                "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
                _ => lease.finish_without_request(),
            }
            .map_err(|_| governor_error())?;
            return Err(failure);
        }
    };
    let contains = |bytes: &[u8]| {
        net::carries_secret(bytes, &input.password)
            || net::carries_secret(bytes, &input.username)
            || session.contains_secret_bytes(bytes)
    };
    enum SelectedRead {
        List(ListRequest),
        Detail(DetailRequest),
    }
    let selected = match input.read {
        SessionRead::List { limit, page, .. } => SelectedRead::List(ListRequest {
            token,
            token_source: Some(TokenSource::RedirectFragmentToken),
            limit,
            page,
            max_pages: 1,
            since_id: None,
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::new(),
            refresh: false,
        }),
        SessionRead::Detail { id, .. } => SelectedRead::Detail(DetailRequest {
            token,
            token_source: Some(TokenSource::RedirectFragmentToken),
            id,
            refresh: false,
        }),
    };
    let token = match &selected {
        SelectedRead::List(read) => read.token.as_str(),
        SelectedRead::Detail(read) => read.token.as_str(),
    };
    // The session's single read still uses one invocation-scoped guard: its
    // issued values are never adopted, transmitted or cached.
    let mut issued = IssuedCookies::default();
    execute_read(
        request,
        &url,
        token,
        lease,
        Some(&contains),
        &mut issued,
        |response, challenge, facts, issues_cookie| {
            // The one-shot session never caches its response, so a session cookie
            // in the read response is not retained here either.
            let _ = issues_cookie;
            admit_body(
                response,
                challenge,
                facts,
                |response, challenge, facts| match &selected {
                    SelectedRead::List(read) => {
                        build_list_envelope(read, [Ok(list_page(read, response, challenge, facts))])
                    }
                    SelectedRead::Detail(read) => Ok(build_detail_envelope(
                        read,
                        detail_page(read, response, challenge, facts),
                    )),
                },
            )
        },
    )
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
    // One guard covers the complete traversal: a cookie issued by any page
    // screens every later fresh or cached page of this invocation.
    let mut issued = IssuedCookies::default();
    list_with_cache(&request, &cache, online, &mut issued)
}

/// The listing traversal over one credential-scoped cache.
fn list_with_cache(
    request: &ListRequest,
    cache: &ResponseCache,
    online: bool,
    issued: &mut IssuedCookies,
) -> Result<Value, Error> {
    collect_list_pages(
        request,
        issued,
        |url, issued| {
            cache.get(
                url,
                request.token.as_str(),
                online,
                request.refresh,
                issued,
                |response, challenge, facts| {
                    Ok::<PageOutcome, Error>(list_page(request, response, challenge, facts))
                },
            )
        },
        |url, issued| purge_cached_admission(cache, url, issued),
    )
}

/// Re-screen one page's replayable cache admission against the complete
/// invocation issued-cookie history. A retained response whose body or
/// headers now match an issued value is removed rather than preserved for a
/// later replay. A prior file that cannot be reviewed as an admission — a
/// pre-cookie-review version, a corrupt record, or a latched rejection — is
/// not proven credential-matching: the existing artifact policy keeps it and
/// its state already prevents publication, so the fresh result stands.
fn purge_cached_admission(
    cache: &ResponseCache,
    url: &Url,
    issued: &IssuedCookies,
) -> Result<(), Error> {
    if issued.is_empty() {
        return Ok(());
    }
    let Ok(Some((response, _))) = cache.load(url) else {
        return Ok(());
    };
    if issued.carries(response.url.as_bytes())
        || response
            .headers
            .values()
            .any(|value| issued.carries(value.as_bytes()))
        || retained_bytes_carry_issued(&response.body, issued)
    {
        cache.remove(url)?;
    }
    Ok(())
}

/// The lazy acquisition hands the invocation's cookie guard to every page
/// read, so each page is screened against every value issued before it. Once
/// the traversal settles, publication re-screens every retained record and
/// every cache admission against the complete history: a value first issued
/// by a later page withholds the earlier records that carried it, never
/// reports the traversal complete, and removes any cached response whose
/// retained content matches.
fn collect_list_pages(
    request: &ListRequest,
    issued: &mut IssuedCookies,
    mut read: impl FnMut(&Url, &mut IssuedCookies) -> Result<PageOutcome, Error>,
    purge: impl FnMut(&Url, &IssuedCookies) -> Result<(), Error>,
) -> Result<Value, Error> {
    // Lazy acquisition lets the collector stop before asking for another
    // page on a terminal, inconsistent, repeated or refused source response.
    let pages = (0..request.max_pages).map(|offset| {
        let page = request.page.saturating_add(offset);
        list_url(request.limit, page).and_then(|url| read(&url, issued))
    });
    let traversal = collect_traversal(request, pages)?;
    publish_list_envelope(request, issued, purge, traversal)
}

/// Strict-TLS service fixtures use the production traversal, cache handling,
/// raw-header admission and lease settlement with a pinned synthetic client
/// and isolated governor. This seam does not exist in a non-test build.
#[cfg(test)]
pub(crate) fn list_with_test_network(
    input: &str,
    cache_directory: &std::path::Path,
    client: Client,
    governor: Governor,
) -> Result<Value, Error> {
    let request = parse_list_input(input)?;
    let cache = ResponseCache {
        directory: governor::open_directory(cache_directory, false, true)
            .map_err(|_| cache_error())?,
    };
    let transport = Transport {
        governor,
        http: client,
    };
    let mut issued = IssuedCookies::default();
    collect_list_pages(
        &request,
        &mut issued,
        |url, issued| {
            transport.fetch(
                &cache,
                url,
                request.token.as_str(),
                request.refresh,
                issued,
                |response, challenge, facts| {
                    Ok(list_page(&request, response, challenge, facts))
                },
            )
        },
        |url, issued| purge_cached_admission(&cache, url, issued),
    )
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
        return credential_echo_page(response, request.token.as_str(), facts.content_type_echo);
    }
    if facts.inspection_incomplete {
        return refused_page(
            response,
            request.token.as_str(),
            FallbackReason::InspectionUnreviewed,
            None,
        );
    }
    if let Some(reason) = response_refusal(response, challenge) {
        return refused_page(response, request.token.as_str(), reason, None);
    }
    if facts.session_denied {
        // An explicit session denial is not an empty listing.
        return refused_page(
            response,
            request.token.as_str(),
            FallbackReason::AuthenticationRefused,
            Some(false),
        );
    }
    let mime = response.headers.get("content-type").map(String::as_str);
    match parse_envelope(mime, facts.document.as_ref()) {
        Ok((pagination, entries)) if entries.len() > request.limit as usize => PageOutcome {
            meta: page_meta(response, entries.len(), request.token.as_str()),
            success: Some(true),
            evidence: Some(evidence(
                FallbackReason::UpstreamShape,
                response,
                request.token.as_str(),
            )),
            entries: Vec::new(),
            pagination,
            source: page_source(response),
        },
        Ok((_, entries)) if cursor_is_incomparable(request, &entries) => refused_page(
            response,
            request.token.as_str(),
            FallbackReason::IncomparableTimestamp,
            Some(true),
        ),
        Ok((pagination, entries)) => PageOutcome {
            meta: page_meta(response, entries.len(), request.token.as_str()),
            success: Some(true),
            evidence: None,
            entries: entries
                .iter()
                .map(|entry| project_entry(entry, response))
                .collect(),
            pagination,
            source: page_source(response),
        },
        Err(reason) => refused_page(
            response,
            request.token.as_str(),
            reason,
            facts
                .document
                .as_ref()
                .and_then(|root| root.get("success"))
                .and_then(Value::as_bool),
        ),
    }
}

/// Read one appeal by its upstream id.
///
/// The id must be supplied explicitly and be the positive id the source
/// published for that appeal: an absent, null or `0` id is refused before any
/// cache or network access. The envelope always reports
/// `upstream.complete`, `upstream.incomplete` and
/// `upstream.incomplete_reason`, so a withheld, unread or empty answer is
/// never presented as a confirmed record.
pub fn detail(input: &str, online: bool) -> Result<Value, Error> {
    let request = parse_detail_input(input)?;
    if request.refresh && !online {
        return Err(invalid_input("refresh requires online authorization"));
    }
    let scope = sha256(request.token.as_bytes());
    let cache = ResponseCache::open(&scope)?;
    let url = detail_url(request.id)?;
    let mut issued = IssuedCookies::default();
    let outcome = cache.get(
        &url,
        request.token.as_str(),
        online,
        request.refresh,
        &mut issued,
        |response, challenge, facts| {
            Ok::<PageOutcome, Error>(detail_page(&request, response, challenge, facts))
        },
    )?;
    Ok(build_detail_envelope(&request, outcome))
}

/// Structure one single-record read. `complete` is true only for a record
/// projected for the requested id; everything else carries the reason it is
/// incomplete.
fn build_detail_envelope(request: &DetailRequest, outcome: PageOutcome) -> Value {
    let degraded = outcome.evidence.is_some();
    let entry = outcome.entries.into_iter().next();
    // A single-record read is complete only when the requested record was
    // actually projected from an accepted positive envelope. A withheld,
    // unparsable or mismatched response is incomplete with its own reason, and
    // an accepted envelope that returns no record for this id stays incomplete
    // too: an empty answer may reflect the account's visibility scope, so it is
    // never promoted to a claimed authoritative absence.
    let incomplete_reason: Option<String> = match outcome.evidence.as_ref() {
        Some(evidence) => Some(
            evidence
                .get("fallback_reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        ),
        None if entry.is_none() => Some("record_not_returned".to_owned()),
        None => None,
    };
    let complete = incomplete_reason.is_none();
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
    json!({
        "schema_version": 1,
        "type": "ihome_appeal_detail",
        "result": result,
        "upstream": {
            "success": outcome.success,
            "id": request.id,
            "complete": complete,
            "incomplete": !complete,
            "incomplete_reason": incomplete_reason,
        },
        "entry": entry,
        "credential_source": request.token_source.map(TokenSource::label),
        "attachments": attachments_notice(),
        "advisory": advisory(),
        "provenance": provenance,
        "upstream_evidence": outcome.evidence,
    })
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
        return credential_echo_page(response, request.token.as_str(), facts.content_type_echo);
    }
    if facts.inspection_incomplete {
        return refused_page(
            response,
            request.token.as_str(),
            FallbackReason::InspectionUnreviewed,
            None,
        );
    }
    if let Some(reason) = response_refusal(response, challenge) {
        return refused_page(response, request.token.as_str(), reason, None);
    }
    if facts.session_denied {
        return refused_page(
            response,
            request.token.as_str(),
            FallbackReason::AuthenticationRefused,
            Some(false),
        );
    }
    let mime = response.headers.get("content-type").map(String::as_str);
    match parse_detail_envelope(mime, facts.document.as_ref()) {
        Ok(Some(entry)) if entry.id != request.id => refused_page(
            response,
            request.token.as_str(),
            FallbackReason::UpstreamShape,
            Some(true),
        ),
        Ok(entry) => PageOutcome {
            meta: page_meta(
                response,
                usize::from(entry.is_some()),
                request.token.as_str(),
            ),
            success: Some(true),
            evidence: None,
            entries: entry
                .map(|entry| vec![project_entry(&entry, response)])
                .unwrap_or_default(),
            pagination: None,
            source: page_source(response),
        },
        Err(reason) => refused_page(
            response,
            request.token.as_str(),
            reason,
            facts
                .document
                .as_ref()
                .and_then(|root| root.get("success"))
                .and_then(Value::as_bool),
        ),
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
        "description": "An explicit ihome bearer token supplied through stdin for a legacy list/detail read; those commands do not log in or refresh it. The separate session command obtains one source-bound fragment token in memory, not through this input. The token is never persisted, logged, echoed, or written to a file. Missing or null tokens are refused with authorization_required before cache or network access. Conservative credential-echo inspection also withholds accidental substring or supported encoded-form matches, especially with short tokens.",
    })
}

fn entry_schema(include_change: bool) -> Value {
    let mut required = vec![
        "id",
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
        "title": {"type": "string", "description": "Copied only when supplied as a string; absent upstream titles remain absent, never derived from content or replaced with null."},
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
            "url": {"type": "string", "description": "The request URL; on a page withheld because an invocation-issued credential value appears in that URL itself, the constant 'withheld'."},
            "url_withheld": {"type": "boolean", "description": "Present and true only when `url` is the 'withheld' marker because the request URL itself carried an invocation-issued credential value."},
            "status": {"type": "integer", "minimum": 100, "maximum": 999},
            "content_type": {"type": ["string", "null"]},
            "content_type_parameters_withheld": {"type":"boolean", "description": "True when the response declared a content type that is not fully projected: untrusted parameters, a malformed value, or a value carrying the submitted credential."},
            "entry_count": {"type": "integer", "minimum": 0},
            "pagination": {
                "type": "object", "additionalProperties": false,
                "required": ["current_page", "last_page", "total"],
                "properties": {
                    "current_page": {"type": "integer", "minimum": 0},
                    "last_page": {"type": "integer", "minimum": 0},
                    "total": {"type": "integer", "minimum": 0}
                },
                "description": "Source-declared numeric pagination when available; its presence alone does not establish that it matches the request."
            },
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
            "fallback_reason": {"enum": ["unexpected_content","upstream_parse","upstream_shape","business_rejected","rate_limited","safety_latched","challenge_unreviewed","redirect_refused","http_rejected","unsupported_encoding","incomparable_timestamp","authentication_refused","credential_echo","inspection_unreviewed"]},
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
        "required": ["upstream_idle_window","inside_idle_window","enforced","note"],
        "properties": {
            "upstream_idle_window": {"type": "null"},
            "inside_idle_window": {"type": "null"},
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
            "download_attachments": {"type": ["boolean", "null"], "default": false, "description": "true is refused with unsupported: no modern attachment download contract has been reviewed and no legacy endpoint is assumed to apply."}
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
            "id": {"type": "integer", "minimum": MIN_APPEAL_ID, "maximum": u64::MAX, "description": "Required positive upstream appeal id observed from the source (for example from a listing entry). It is never defaulted: an absent or null id is refused, and 0 is refused as an invented placeholder before any cache or network access."},
            "refresh": {"type": ["boolean", "null"], "default": false, "description": "Explicitly fetch fresh data, bypassing the cache; requires --online. Absent or null is false."},
            "download_attachments": {"type": ["boolean", "null"], "default": false, "description": "true is refused with unsupported: attachment download is not implemented and the upstream attachment contract is unknown."}
        }
    })
}

fn session_input_schema() -> Value {
    json!({
        "type":"object", "additionalProperties":false,
        "required":["authorized","username","password","intent","read"],
        "description":"One deliberate CAS attempt and exactly one selected read. JSON objects only, at most 64 KiB; duplicate and unknown fields are refused. Disabled reads perform no authentication or I/O. No caller token, cookie, URL, refresh, mutation or multi-page traversal is accepted.",
        "properties":{
            "operation":{"const":"session"},
            "authorized":{"type":"boolean"},
            "username":{"type":"string","description":"Operator credentials via private stdin only; validated before an enabled attempt."},
            "password":{"type":"string","writeOnly":true},
            "intent":{"type":"string","description":"Exact LOGIN <username> ihome for an enabled attempt."},
            "read":{"oneOf":[
                {"type":"object","additionalProperties":false,"required":["operation","enabled"],"properties":{
                    "operation":{"const":"list"},"enabled":{"type":"boolean"},
                    "limit":{"type":"integer","minimum":1,"maximum":MAX_LIMIT,"default":DEFAULT_LIMIT},
                    "page":{"type":"integer","minimum":1,"maximum":MAX_PAGE,"default":1}}},
                {"type":"object","additionalProperties":false,"required":["operation","enabled","id"],"properties":{
                    "operation":{"const":"detail"},"enabled":{"type":"boolean"},
                    "id":{"type":"integer","minimum":MIN_APPEAL_ID,"maximum":u64::MAX,"description":"Required positive upstream appeal id observed from the source; 0 is refused as an invented placeholder before any authentication or read."}}}
            ]}
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
            "session_input": session_input_schema(),
            "run_list_input": run_input_schema("list", list_input_schema()),
            "run_detail_input": run_input_schema("detail", detail_input_schema()),
            "run_session_input": run_input_schema("session", session_input_schema())
        },
        "run": {
            "input": {
                "type": "object",
                "description": "The operation selects list/detail with an explicit bearer token, or session with one deliberately supplied credential pair and one selected read. Each operation retains its own strict input contract.",
                "oneOf": [
                    run_input_schema("list", list_input_schema()),
                    run_input_schema("detail", detail_input_schema()),
                    run_input_schema("session", session_input_schema())
                ]
            },
            "options": {
                "--online": "Permit a token-read cache miss, or one explicit session authentication followed by one selected read. refresh:true belongs only to token reads. No automatic retry."
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
                    "result": {"enum": ["entries","empty","partial","degraded"], "description": "empty requires an accepted positive envelope with no emitted entries; partial preserves valid records when pagination is unconfirmed, inconsistent, repeated or interrupted; degraded reports a refusal or parse failure with safe original evidence, never an invented empty business result."},
                    "upstream": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["success","pages","complete","incomplete","incomplete_reason"],
                        "properties": {
                            "success": {"type": ["boolean","null"], "description": "The observed Boolean upstream flag, not HTTP or business acceptance. Business acceptance additionally requires numeric code=20000. Negative and malformed business envelopes degrade; explicit authentication denial is separately classified."},
                            "pages": {"type": "array", "items": page_meta_schema()},
                            "complete": {"type": "boolean", "description": "True only at a source-declared terminal page with matching page, count, total and limit facts throughout this requested traversal; it does not establish earlier history before the requested start page."},
                            "incomplete": {"type": "boolean", "description": "True for missing/inconsistent pagination, changing totals, duplicate ids, or later acquisition failure. Valid records remain published without cursor advancement."},
                            "incomplete_reason": {"type": ["string","null"], "description": "Pagination/duplicate refusal or later acquisition error code; null for a consistent bounded window, which may still have more pages."}
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
                    "result": {"enum": ["appeal","not_found","degraded"], "description": "appeal carries one record projected for the requested id; not_found means the accepted positive envelope returned no record for that id and is reported as incomplete, because an empty answer may reflect the account's visibility scope; degraded reports a withheld, refused or unparsable response with its reason and never invents a record."},
                    "upstream": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["success","id","complete","incomplete","incomplete_reason"],
                        "properties": {
                            "success": {"type": ["boolean", "null"], "description": "The observed Boolean upstream flag, not HTTP or business acceptance. Business acceptance separately requires numeric code=20000."},
                            "id": {"type": "integer", "minimum": MIN_APPEAL_ID, "maximum": u64::MAX, "description": "The explicit positive source id this read requested; it is never defaulted or invented, and a projected record must carry the same id."},
                            "complete": {"type": "boolean", "description": "True only when one record for the requested id was projected from an accepted numeric code=20000 and success=true envelope with no withheld evidence."},
                            "incomplete": {"type": "boolean", "description": "True whenever nothing was acquired for the requested id, including a response that was withheld or unparsable and an accepted envelope that returned no record."},
                            "incomplete_reason": {"type": ["string","null"], "description": "The fallback reason code of a withheld, refused or unparsable response, or record_not_returned when an accepted positive envelope declared no record for this id; null only when complete is true."}
                        }
                    },
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
            "attachment_download": "No modern attachment-download contract has been reviewed. Legacy php-ihome routes belong to a different historical social platform and are not endpoint evidence for this appeal service. Extraction covers recognized declared absolute URLs in body_data/image fields only, not a complete inventory; nonempty annex layouts and remote existence remain unverified. No URL is fetched.",
            "webvpn": "WebVPN URL encryption is an upstream client-side detail. It is documented here and deliberately not implemented; only direct HTTPS to i.buaa.edu.cn is used.",
            "idle_window": "The current upstream idle window is unknown; no time-based protection is asserted or enforced.",
            "login": "session implements one explicit in-memory source-bound CAS attempt and one fixed HTTPS read, without persistence, refresh or retry. Its current live deployment and account identity remain unverified. Existing list/detail still require an explicit bearer token.",
            "online_acceptance": "This adapter has not been exercised against the live campus service; its online acceptance is still unverified."
        }
    });
    // The run and session output contracts are published as standalone
    // schemas, so every variant is inlined. A fragment reference resolves
    // against the root of the whole published document, where these
    // definitions do not live.
    let list_output = contract["list"]["output"].clone();
    let detail_output = contract["detail"]["output"].clone();
    let disabled_session_output = json!({
        "type":"object","additionalProperties":false,
        "required":["schema_version","type","result","network_performed","write_operations_performed"],
        "properties":{"schema_version":{"const":1},"type":{"const":"ihome_session"},
            "result":{"const":"disabled"},"network_performed":{"const":false},"write_operations_performed":{"const":false}}
    });
    let output = json!({"oneOf":[list_output, detail_output, disabled_session_output]});
    contract["run"]["output"] = output.clone();
    contract["session"] = json!({
        "input":session_input_schema(),
        "options":{"--online":"Required for an enabled one-shot authentication and read. All actual requests use HTTPS, no terminal credential URL is fetched, and no automatic login refresh/retry occurs."},
        "output":output
    });
    contract
}

#[cfg(test)]
mod session_preflight {
    use super::*;

    #[test]
    fn disabled_or_unapproved_reads_never_open_authentication_resources() {
        let input = json!({"authorized":true,"username":"synthetic-operator-4b7",
            "password":"synthetic-password-9q2","intent":"LOGIN synthetic-operator-4b7 ihome",
            "read":{"operation":"list","enabled":true}});
        for read in [
            json!({"operation":"list","enabled":false}),
            json!({"operation":"detail","enabled":false,"id":42}),
        ] {
            let mut disabled = input.clone();
            disabled["read"] = read;
            disabled["authorized"] = json!(false);
            disabled["username"] = json!("");
            disabled["password"] = json!("");
            disabled["intent"] = json!("");
            let output = session_with_network(&disabled.to_string(), true, || {
                panic!("disabled read opened network resources")
            })
            .unwrap();
            assert_eq!(output["result"], "disabled");
            assert_eq!(output["network_performed"], false);
        }
        let mut unauthorized = input.clone();
        unauthorized["authorized"] = json!(false);
        let mut mismatched = input.clone();
        mismatched["intent"] = json!("LOGIN another-operator ihome");
        let mut out_of_range = input.clone();
        out_of_range["read"]["limit"] = json!(101);
        for (input, online, expected) in [
            (unauthorized, true, "permission"),
            (mismatched, true, "invalid_input"),
            (out_of_range, true, "invalid_input"),
            (input, false, "online_required"),
        ] {
            let failure = session_with_network(&input.to_string(), online, || {
                panic!("unapproved read opened authentication resources")
            })
            .unwrap_err();
            assert_eq!(failure.code, expected);
        }
    }
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
            token: Zeroizing::new(token.to_owned()),
            token_source: None,
            limit: 20,
            page: 1,
            max_pages: 1,
            since_id: None,
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::new(),
            refresh: false,
        };
        let detail = DetailRequest {
            token: Zeroizing::new(token.to_owned()),
            token_source: None,
            id: 41,
            refresh: false,
        };
        let listing = list_page(&list, &response, &ChallengeAssessment::Clear, &facts);
        let detail = detail_page(&detail, &response, &ChallengeAssessment::Clear, &facts);
        (facts, listing, detail)
    }

    fn assert_refusal(page: &PageOutcome, reason: &str) {
        assert!(page.entries.is_empty());
        let evidence = page.evidence.as_ref().expect("refusal evidence");
        assert!(
            evidence.get("raw_response_base64").is_none(),
            "reversible raw response leaked"
        );
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
        assert!(
            facts.session_denied,
            "explicit denial must survive the marker"
        );
        assert!(facts.token_echo, "short exact token must be detected");
        // Credential privacy takes precedence in projection, while the denial
        // fact remains available independently for governor settlement.
        assert_refusal(&listing, "credential_echo");
        assert_refusal(&detail, "credential_echo");
    }

    #[test]
    fn denial() {
        let body =
            br#"{"$serde_json::private::RawValue":"","success":false,"message":"unauthorized"}"#;
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
        let (facts, listing, detail) = pages(
            br#"{"code":20000,"success":true,"data":{"data":[]}}"#,
            "abc_123",
        );
        assert!(!facts.token_echo && !facts.session_denied);
        for page in [&listing, &detail] {
            assert_eq!(page.success, Some(true));
            assert!(page.evidence.is_none());
        }

        for (body, token) in [
            (br#"{"message":"abc_123"}"#.as_slice(), "abc_123"),
            (
                br#"{"message":"prefix abc_1234 suffix"}"#.as_slice(),
                "abc_1234",
            ),
        ] {
            let (facts, listing, detail) = pages(body, token);
            assert!(facts.token_echo);
            assert_refusal(&listing, "credential_echo");
            assert_refusal(&detail, "credential_echo");
        }
        // The marker is an ordinary member, not an encoded replacement root.
        let body = br#"{"$serde_json::private::RawValue":"{\"success\":false,\"message\":\"unauthorized\"}","code":20000,"success":true,"data":{"data":[]}}"#;
        let (facts, listing, _) = pages(body, "abc_123");
        assert!(!facts.session_denied && !facts.token_echo);
        assert_eq!(listing.success, Some(true));
        let (facts, listing, _) = pages(
            br#"{"$serde_json::private::RawValue":"ordinary"}"#,
            "abc_123",
        );
        assert!(!facts.token_echo && !facts.session_denied);
        let fallback = listing.evidence.as_ref().unwrap();
        assert_eq!(fallback["evidence_kind"], "upstream_http_body");
        assert!(fallback.get("raw_response_base64").is_some());
        let (facts, _, _) = pages(
            br#"{"$serde_json::private::RawValue":"1234567"}"#,
            "1234567",
        );
        assert!(facts.token_echo);
        let (facts, _, _) = pages(br#"{"echo":"abc_123","echo":"safe","success":false,"message":"unauthorized","success":true}"#, "abc_123");
        assert!(facts.token_echo && !facts.session_denied);
        let (facts, _, _) = pages(
            br#"{"nested":"{\"$serde_json::private::RawValue\":\"\\u0061bc_123\"}"}"#,
            "abc_123",
        );
        assert!(facts.token_echo);

        let (facts, _, _) = pages(br#"{"value":"\ud83d\ude00"}"#, "😀");
        assert!(facts.token_echo);
        let (facts, _, _) = pages(br#"{"value":"YWJj"}"#, "abc");
        assert!(facts.token_echo);

        let mut urls = Vec::new();
        collect_declared_urls(
            &Value::String(
                r#"{"$serde_json::private::RawValue":"\"https://example.invalid/file\""}"#
                    .to_owned(),
            ),
            &mut urls,
            0,
        );
        assert!(urls.is_empty());
        collect_declared_urls(
            &Value::String(r#"{"url":"https://example.invalid/file"}"#.to_owned()),
            &mut urls,
            0,
        );
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
        "code": 20000,
        "success": true,
        "data": {
            "current_page": 1,
            "last_page": 1,
            "total": 2,
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
            Ok((pagination, entries)) => PageOutcome {
                meta: page_meta(&original, entries.len(), "synthetic-token-value"),
                success: Some(true),
                evidence: None,
                entries: entries
                    .iter()
                    .map(|entry| project_entry(entry, &original))
                    .collect(),
                pagination,
                source: page_source(&original),
            },
            Err(reason) => refused_page(&original, "synthetic-token-value", reason, None),
        }
    }

    fn source_page(current: u32, last: u32, total: u64, ids: &[u64]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "code": 20000,
            "success": true,
            "data": {
                "current_page": current, "last_page": last, "total": total,
                "data": ids.iter().map(|id| json!({
                    "id": id, "title": "Source-supplied title", "content": "Synthetic appeal body",
                    "created_at": "2026-10-20 08:30:00", "publish_status_text": "Pending",
                    "departments": [], "appeal_reply": []
                })).collect::<Vec<_>>()
            }
        }))
        .unwrap()
    }

    fn source_outcome(request: &ListRequest, page: u32, body: &[u8]) -> PageOutcome {
        let original = response(
            &list_url(request.limit, page).unwrap(),
            body,
            Some("application/json"),
        );
        let facts = analyze_body(body, request.token.as_str());
        list_page(request, &original, &ChallengeAssessment::Clear, &facts)
    }

    #[test]
    fn source_protocol_preserves_untitled_list_and_detail_records() {
        let mut document: Value = serde_json::from_slice(&source_page(1, 1, 1, &[41])).unwrap();
        document["data"]["data"][0]
            .as_object_mut()
            .unwrap()
            .remove("title");
        let body = serde_json::to_vec(&document).unwrap();
        let request = list_request(20);
        let envelope = build_list_envelope(
            &request,
            (vec![source_outcome(&request, 1, &body)])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
        assert_eq!(envelope["result"], "entries");
        assert_eq!(envelope["entries"][0]["id"], 41);
        assert_eq!(envelope["entries"][0]["content"], "Synthetic appeal body");
        assert_eq!(envelope["entries"][0]["created_at"], "2026-10-20 08:30:00");
        assert!(envelope["entries"][0].get("title").is_none());

        let detail_body = serde_json::to_vec(&json!({
            "code": 20000, "success": true, "data": document["data"]["data"][0]
        }))
        .unwrap();
        let original = response(
            &detail_url(41).unwrap(),
            &detail_body,
            Some("application/json"),
        );
        let facts = analyze_body(&detail_body, request.token.as_str());
        let detail = DetailRequest {
            token: Zeroizing::new(request.token.to_string()),
            token_source: None,
            id: 41,
            refresh: false,
        };
        let outcome = detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts);
        assert!(outcome.evidence.is_none());
        assert_eq!(outcome.entries[0]["content"], "Synthetic appeal body");
        assert!(outcome.entries[0].get("title").is_none());
    }

    #[test]
    fn a_detail_envelope_states_completeness_without_inventing_a_record() {
        let request = parse_detail_input(r#"{"token":"synthetic-token","id":41}"#).unwrap();
        let entry = r#"{"id":41,"title":"Quiet hallway","content":"ordinary appeal","created_at":"2026-10-20 08:30:00","publish_status_text":"Pending","departments":[],"appeal_reply":[]}"#;

        // The requested record from an accepted positive envelope is complete.
        let body = format!(r#"{{"code":20000,"success":true,"data":{entry}}}"#);
        let original = response(
            &detail_url(41).unwrap(),
            body.as_bytes(),
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, request.token.as_str());
        let envelope = build_detail_envelope(
            &request,
            detail_page(&request, &original, &ChallengeAssessment::Clear, &facts),
        );
        assert_eq!(envelope["result"], "appeal");
        assert_eq!(envelope["upstream"]["id"], 41);
        assert_eq!(envelope["upstream"]["complete"], true);
        assert_eq!(envelope["upstream"]["incomplete"], false);
        assert!(envelope["upstream"]["incomplete_reason"].is_null());
        assert_eq!(envelope["entry"]["id"], 41);
        assert!(envelope["upstream_evidence"].is_null());

        // A record for another id is never relabeled as the requested appeal.
        let body = format!(
            r#"{{"code":20000,"success":true,"data":{}}}"#,
            entry.replace("\"id\":41", "\"id\":42")
        );
        let original = response(
            &detail_url(41).unwrap(),
            body.as_bytes(),
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, request.token.as_str());
        let envelope = build_detail_envelope(
            &request,
            detail_page(&request, &original, &ChallengeAssessment::Clear, &facts),
        );
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["upstream"]["id"], 41);
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["upstream"]["incomplete"], true);
        assert_eq!(envelope["upstream"]["incomplete_reason"], "upstream_shape");
        assert!(envelope["entry"].is_null());

        // An accepted envelope that returns no record for this id is not a
        // claimed absence: it stays incomplete with an explicit reason.
        let body = br#"{"code":20000,"success":true,"data":{"data":[]}}"#.as_slice();
        let original = response(&detail_url(41).unwrap(), body, Some("application/json"));
        let facts = analyze_body(&original.body, request.token.as_str());
        let envelope = build_detail_envelope(
            &request,
            detail_page(&request, &original, &ChallengeAssessment::Clear, &facts),
        );
        assert_eq!(envelope["result"], "not_found");
        assert!(envelope["entry"].is_null());
        assert_eq!(envelope["upstream"]["id"], 41);
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["upstream"]["incomplete"], true);
        assert_eq!(
            envelope["upstream"]["incomplete_reason"],
            "record_not_returned"
        );

        // A refused response keeps its own reason instead of a placeholder.
        let body =
            br#"{"code":40001,"success":false,"message":"ordinary business rejection"}"#.as_slice();
        let original = response(&detail_url(41).unwrap(), body, Some("application/json"));
        let facts = analyze_body(&original.body, request.token.as_str());
        let envelope = build_detail_envelope(
            &request,
            detail_page(&request, &original, &ChallengeAssessment::Clear, &facts),
        );
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(
            envelope["upstream"]["incomplete_reason"],
            "business_rejected"
        );
        assert!(envelope["entry"].is_null());

        // The published contract states the same facts: a detail read requires
        // a positive id and always reports completeness.
        let contract = schema();
        assert_eq!(
            contract["detail"]["input"]["properties"]["id"]["minimum"],
            1
        );
        let required = contract["detail"]["output"]["properties"]["upstream"]["required"]
            .as_array()
            .expect("upstream required members");
        for field in [
            "success",
            "id",
            "complete",
            "incomplete",
            "incomplete_reason",
        ] {
            assert!(
                required.iter().any(|value| value.as_str() == Some(field)),
                "{field}"
            );
        }
    }

    #[test]
    fn source_protocol_requires_positive_business_code_and_success() {
        let request = list_request(20);
        let detail = DetailRequest {
            token: Zeroizing::new(request.token.to_string()),
            token_source: None,
            id: 41,
            refresh: false,
        };
        for (body, reason) in [
            (
                br#"{"code":40001,"success":false,"message":"ordinary business rejection"}"#
                    .as_slice(),
                "business_rejected",
            ),
            (
                br#"{"code":40001,"success":"","message":"ordinary business rejection"}"#
                    .as_slice(),
                "business_rejected",
            ),
            (
                br#"{"code":20000,"success":false,"data":{"data":[]}}"#.as_slice(),
                "business_rejected",
            ),
            (
                br#"{"code":40001,"success":true,"data":{"data":[]}}"#.as_slice(),
                "business_rejected",
            ),
            (
                br#"{"success":true,"data":{"data":[]}}"#.as_slice(),
                "upstream_shape",
            ),
            (
                br#"{"code":"20000","success":true,"data":{"data":[]}}"#.as_slice(),
                "upstream_shape",
            ),
        ] {
            let facts = analyze_body(body, request.token.as_str());
            assert!(!facts.session_denied && !facts.token_echo);
            let original = response(&detail_url(41).unwrap(), body, Some("application/json"));
            for page in [
                source_outcome(&request, 1, body),
                detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts),
            ] {
                let found = page
                    .evidence
                    .as_ref()
                    .expect("business rejection must not become an empty result");
                assert_eq!(found["fallback_reason"], reason);
                assert_eq!(
                    STANDARD
                        .decode(found["raw_response_base64"].as_str().unwrap())
                        .unwrap(),
                    body
                );
                assert!(page.entries.is_empty());
            }
        }
    }

    #[test]
    fn source_protocol_does_not_complete_missing_or_mismatched_pagination() {
        let request = list_request(20);
        for (mut document, reason) in [
            (
                serde_json::from_slice::<Value>(&source_page(1, 1, 1, &[41])).unwrap(),
                "pagination_unconfirmed",
            ),
            (
                serde_json::from_slice::<Value>(&source_page(2, 2, 21, &[41])).unwrap(),
                "page_mismatch",
            ),
            (
                serde_json::from_slice::<Value>(&source_page(1, 1, 21, &[41])).unwrap(),
                "pagination_inconsistent",
            ),
        ] {
            if reason == "pagination_unconfirmed" {
                document["data"]
                    .as_object_mut()
                    .unwrap()
                    .remove("current_page");
            }
            let body = serde_json::to_vec(&document).unwrap();
            let envelope = build_list_envelope(
                &request,
                (vec![source_outcome(&request, 1, &body)])
                    .into_iter()
                    .map(Ok),
            )
            .unwrap();
            assert_eq!(envelope["result"], "partial");
            assert_eq!(envelope["entries"][0]["id"], 41);
            assert_eq!(envelope["upstream"]["complete"], false);
            assert_eq!(envelope["upstream"]["incomplete_reason"], reason);
            assert_eq!(envelope["next_cursor"], Value::Null);
        }
    }

    #[test]
    fn source_protocol_short_page_is_not_terminal_without_matching_totals() {
        let request = list_request(20);
        let body = source_page(1, 2, 21, &[41]);
        let envelope = build_list_envelope(
            &request,
            (vec![source_outcome(&request, 1, &body)])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
        assert_eq!(envelope["result"], "partial");
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["next_cursor"], Value::Null);
    }

    #[test]
    fn source_protocol_full_last_page_is_complete_and_empty_total_is_empty() {
        let request = list_request(2);
        let body = source_page(1, 1, 2, &[41, 42]);
        let envelope = build_list_envelope(
            &request,
            (vec![source_outcome(&request, 1, &body)])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
        assert_eq!(envelope["upstream"]["complete"], true);
        assert_eq!(envelope["next_cursor"]["has_more"], false);
        assert_eq!(envelope["next_cursor"]["max_id"], 42);
        let body = source_page(1, 1, 0, &[]);
        let envelope = build_list_envelope(
            &request,
            (vec![source_outcome(&request, 1, &body)])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
        assert_eq!(envelope["result"], "empty");
        assert_eq!(envelope["upstream"]["complete"], true);
    }

    #[test]
    fn source_protocol_missing_collections_and_invalid_titles_do_not_invent_facts() {
        let request = list_request(20);
        for field in ["departments", "appeal_reply", "title"] {
            let mut document: Value = serde_json::from_slice(&source_page(1, 1, 1, &[41])).unwrap();
            if field == "title" {
                document["data"]["data"][0][field] = Value::Null;
            } else {
                document["data"]["data"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
            }
            let body = serde_json::to_vec(&document).unwrap();
            let envelope =
                build_list_envelope(&request, [Ok(source_outcome(&request, 1, &body))]).unwrap();
            assert_eq!(envelope["result"], "degraded");
            assert_eq!(envelope["next_cursor"], Value::Null);
            let found = &envelope["upstream_evidence"];
            assert_eq!(found["fallback_reason"], "upstream_shape");
            assert_eq!(
                STANDARD
                    .decode(found["raw_response_base64"].as_str().unwrap())
                    .unwrap(),
                body
            );
        }
    }

    #[test]
    fn source_protocol_changing_totals_prevent_incremental_cursor_advancement() {
        let request = list_request(2);
        let pages = [
            Ok(source_outcome(
                &request,
                1,
                &source_page(1, 2, 3, &[41, 42]),
            )),
            Ok(source_outcome(
                &request,
                2,
                &source_page(2, 2, 4, &[43, 44]),
            )),
        ];
        let envelope = build_list_envelope(&request, pages).unwrap();
        assert_eq!(envelope["result"], "partial");
        assert_eq!(envelope["entry_count"], 4);
        assert_eq!(
            envelope["upstream"]["incomplete_reason"],
            "pagination_changed"
        );
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["next_cursor"], Value::Null);
    }

    #[test]
    fn source_protocol_more_records_than_requested_retains_safe_original_without_cursor() {
        let request = list_request(1);
        let body = source_page(1, 1, 2, &[41, 42]);
        let envelope =
            build_list_envelope(&request, [Ok(source_outcome(&request, 1, &body))]).unwrap();
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["next_cursor"], Value::Null);
        assert_eq!(
            STANDARD
                .decode(
                    envelope["upstream_evidence"]["raw_response_base64"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
            body
        );
    }

    #[test]
    fn source_protocol_valid_traversal_stops_at_declared_full_last_page() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-terminal-pages-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        for (page, ids) in [(1, [41, 42]), (2, [43, 44]), (3, [45, 46])] {
            let body = source_page(page, 2, 4, &ids);
            cache
                .save(
                    &response(&list_url(2, page).unwrap(), &body, Some("application/json")),
                    &ChallengeAssessment::Clear,
                )
                .unwrap();
        }
        let mut request = list_request(2);
        request.max_pages = 3;
        let envelope =
            list_with_cache(&request, &cache, false, &mut IssuedCookies::default()).unwrap();
        assert_eq!(envelope["upstream"]["complete"], true);
        assert_eq!(envelope["upstream"]["pages"].as_array().unwrap().len(), 2);
        assert_eq!(
            envelope["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["id"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [41, 42, 43, 44]
        );
        assert_eq!(envelope["next_cursor"]["has_more"], false);
        assert_eq!(envelope["next_cursor"]["max_id"], 44);
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn source_protocol_repeated_ids_stop_before_the_following_cached_page() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-source-pages-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        for page in 1..=3 {
            let body = source_page(page, 3, 6, if page == 3 { &[43, 44] } else { &[41, 42] });
            cache
                .save(
                    &response(&list_url(2, page).unwrap(), &body, Some("application/json")),
                    &ChallengeAssessment::Clear,
                )
                .unwrap();
        }
        let mut request = list_request(2);
        request.max_pages = 3;
        let envelope =
            list_with_cache(&request, &cache, false, &mut IssuedCookies::default()).unwrap();
        assert_eq!(
            envelope["upstream"]["pages"].as_array().unwrap().len(),
            2,
            "a repeated page must stop traversal before page three"
        );
        assert_eq!(
            envelope["upstream"]["incomplete_reason"],
            "duplicate_entry_id"
        );
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(envelope["next_cursor"], Value::Null);
        assert_eq!(
            envelope["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["id"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [41, 42]
        );
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn listing_is_normalized_with_declared_attachments_only() {
        let request = list_request(20);
        let envelope = build_list_envelope(
            &request,
            (vec![page_from(LIST_BODY, Some("application/json"))])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
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
        let body = br#"{"code":20000,"success":true,"data":{"data":{"id":41,"title":"Dormitory heating","content":"Body","created_at":"2026-10-20 08:30:00","publish_status_text":"Replied","departments":[{"id":3,"name":"Logistics"}],"appeal_reply":[{"id":900,"department":{"id":3,"name":"Logistics"},"content":"Reply","created_at":"2026-10-21 09:00:00"}]}}}"#;
        let original = response(&url, body, Some("application/json"));
        let observed = content_type(&original, "synthetic-token-value");
        let facts = analyze_body(&original.body, "synthetic-token-value");
        let entry = parse_detail_envelope(observed.as_deref(), facts.document.as_ref()).unwrap();
        let entry = entry.unwrap();
        assert_eq!(entry.id, 41);
        assert_eq!(entry.created_at, "2026-10-20 08:30:00");
        assert_eq!(entry.replies[0].created_at, "2026-10-21 09:00:00");
        assert_eq!(entry.status, "Replied");

        let direct = br#"{"code":20000,"success":true,"data":{"id":41,"title":"t","content":"c","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}}"#;
        let direct_facts = analyze_body(direct, "synthetic-token-value");
        assert_eq!(
            parse_detail_envelope(Some("application/json"), direct_facts.document.as_ref())
                .unwrap()
                .unwrap()
                .id,
            41
        );
    }

    #[test]
    fn an_empty_page_is_reported_as_empty_with_a_cursor() {
        let body = br#"{"code":20000,"success":true,"data":{"data":[],"current_page":1,"last_page":1,"total":0}}"#;
        let request = list_request(20);
        let envelope = build_list_envelope(
            &request,
            (vec![page_from(body, Some("application/json"))])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
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

        let request =
            parse_list_input(r#"{"token":"synthetic-token","limit":0,"page":1,"max_pages":1}"#)
                .err()
                .unwrap();
        assert_eq!(request.code, "invalid_input");
        let pages =
            parse_list_input(r#"{"token":"synthetic-token","limit":20,"page":1,"max_pages":21}"#)
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
        let envelope = build_list_envelope(
            &request,
            (vec![page_from(LIST_BODY, Some("application/json"))])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
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
        let envelope = build_list_envelope(
            &request,
            (vec![page_from(LIST_BODY, Some("application/json"))])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
        assert_eq!(envelope["entry_count"], 1);
        assert_eq!(envelope["entries"][0]["id"], 41);
        assert_eq!(envelope["dedup"]["skipped_unchanged"], 1);
        assert_eq!(envelope["dedup"]["kept_new"], 1);
    }

    #[test]
    fn changed_known_record_is_not_hidden_by_an_id_cursor() {
        let mut request = list_request(20);
        request.since_id = Some(100);
        request.known.insert(
            41,
            KnownItem {
                id: 41,
                status: "Pending".into(),
                reply_count: 1,
            },
        );
        let envelope = build_list_envelope(
            &request,
            (vec![page_from(LIST_BODY, Some("application/json"))])
                .into_iter()
                .map(Ok),
        )
        .unwrap();
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
        let floating =
            parse_list_input(r#"{"token":"synthetic-token","since_time":"2026-10-20 08:30:00"}"#)
                .unwrap();
        let accepted = parse_list_input(
            r#"{"token":"synthetic-token","since_time":"2026-10-20T08:30:00+08:00"}"#,
        )
        .unwrap();
        assert!(
            compare_timestamps(
                floating.since_time.as_ref().unwrap(),
                accepted.since_time.as_ref().unwrap()
            )
            .is_none()
        );
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
        let mut list: ListInput =
            serde_json::from_str(r#"{"token":"synthetic-secret","operation":"list"}"#).unwrap();
        let secret: Zeroizing<String> = list.token.take().unwrap();
        assert_eq!(secret.as_str(), "synthetic-secret");
        let detail: DetailInput =
            serde_json::from_str(r#"{"token":"synthetic-secret","id":41}"#).unwrap();
        let _: &Zeroizing<String> = detail.token.as_ref().unwrap();
        assert!(
            serde_json::from_str::<ListInput>(r#"{"token":null}"#)
                .unwrap()
                .token
                .is_none()
        );
        assert!(
            serde_json::from_str::<ListInput>("{}")
                .unwrap()
                .token
                .is_none()
        );
    }

    #[test]
    fn documented_object_inputs_reject_positional_arrays() {
        for input in [
            r#"["synthetic-token","list",null,20,1,1,null,null,null,false,false]"#,
            r#"["synthetic-token","detail",null,41,false,false]"#,
        ] {
            assert!(serde_json::from_str::<ListInput>(input).is_err());
            assert!(serde_json::from_str::<DetailInput>(input).is_err());
            assert_eq!(run(input, false).err().unwrap().code, "invalid_input");
        }
        assert!(serde_json::from_str::<OperationSelector>(r#"["list"]"#).is_err());
        for input in [
            r#"{"operation":"list","token":"synthetic-secret","known":[[41,"Pending",0]]}"#,
            r#"{"operation":"list","token":"synthetic-secret","known":[{"id":41,"status":"Pending","reply_count":0},[42,"Pending",0]]}"#,
        ] {
            let error = run(input, false).err().unwrap();
            assert_eq!(error.code, "invalid_input");
            assert!(!error.message.contains("synthetic-secret"));
        }
        // The collection remains an array, but each member must be an object.
        let accepted=parse_list_input(r#"{"operation":"list","token":"synthetic-secret","known":[{"id":41,"status":"Pending","reply_count":0}]}"#).unwrap();
        assert_eq!(accepted.known.len(), 1);
        assert_eq!(accepted.known[&41].reply_count, 0);
        assert!(
            parse_detail_input(r#"{"operation":"detail","token":"synthetic-secret","id":41}"#)
                .is_ok()
        );
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
            assert_eq!(
                parse_detail_input(input).err().unwrap().code,
                "invalid_input"
            );
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
        let error = parse_list_input(r#"{"token":"synthetic-token","download_attachments":true}"#)
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
    fn a_detail_read_requires_an_explicit_source_shaped_id() {
        // No defaulted id: an absent or null id is refused, never read as 0.
        for input in [
            r#"{"token":"synthetic-token"}"#,
            r#"{"token":"synthetic-token","id":null}"#,
        ] {
            let error = parse_detail_input(input).err().unwrap();
            assert_eq!(error.code, "invalid_input");
            assert!(
                error.message.contains("explicit upstream appeal id"),
                "{}",
                error.message
            );
            assert!(!error.message.contains("synthetic-token"));
        }
        // 0 is not an id the source produces: it can only be a placeholder for
        // a record the caller never named, so it is refused before any access.
        let zero = parse_detail_input(r#"{"token":"synthetic-token","id":0}"#)
            .err()
            .unwrap();
        assert_eq!(zero.code, "invalid_input");
        assert!(zero.message.contains("positive upstream appeal id"));
        // Non-integer spellings never decode into an id at all.
        for input in [
            r#"{"token":"synthetic-token","id":-1}"#,
            r#"{"token":"synthetic-token","id":1.5}"#,
            r#"{"token":"synthetic-token","id":"41"}"#,
        ] {
            assert!(
                serde_json::from_str::<DetailInput>(input).is_err(),
                "{input}"
            );
            assert_eq!(
                parse_detail_input(input).err().unwrap().code,
                "invalid_input"
            );
        }
        // A supplied source id is preserved verbatim.
        assert_eq!(
            parse_detail_input(r#"{"token":"synthetic-token","id":1}"#)
                .unwrap()
                .id,
            1
        );
        assert_eq!(
            parse_detail_input(r#"{"token":"synthetic-token","id":41}"#)
                .unwrap()
                .id,
            41
        );
        // The same guard owns the URL: no invented path is ever built, and an
        // admitted path must be the canonical decimal spelling of a positive
        // id rather than merely all digits.
        assert_eq!(detail_url(0).err().unwrap().code, "invalid_input");
        let admitted = detail_url(41).unwrap();
        assert_eq!(admitted.as_str(), "https://i.buaa.edu.cn/api/appeal/41");
        assert!(allowed_url(&admitted));
        for path in ["/api/appeal/0", "/api/appeal/007", "/api/appeal/"] {
            let url = Url::parse(&format!("https://i.buaa.edu.cn{path}")).unwrap();
            assert!(!allowed_url(&url), "{path}");
        }
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
        let envelope = build_list_envelope(&request, (vec![page]).into_iter().map(Ok)).unwrap();
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["entry_count"], 0);
        assert_eq!(envelope["next_cursor"], Value::Null);
        assert_eq!(envelope["upstream_evidence"]["sha256"], sha256(body));
    }

    #[test]
    fn private_cache_rereads_exact_degraded_body_and_content_type_offline() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-fixture-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        let bytes = b"<html>synthetic refusal\0\xff</html>";
        let mut original = response(&url, bytes, Some("text/html; charset=UTF-8"));
        original.status = 403;
        cache
            .save(&original, &ChallengeAssessment::Detected)
            .unwrap();
        let (saved, challenge) = cache.load(&url).unwrap().unwrap();
        assert!(matches!(challenge, ChallengeAssessment::Detected));
        assert_eq!(saved.status, 403);
        assert_eq!(saved.body.as_slice(), &bytes[..]);
        let raw = evidence(
            response_refusal(&saved, &challenge).unwrap(),
            &saved,
            "synthetic-token-value",
        );
        assert_eq!(raw["fallback_reason"], "safety_latched");
        assert_eq!(raw["content_type"], "text/html");
        assert_eq!(raw["content_type_parameters_withheld"], true);
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
        let envelope = build_list_envelope(&request, (vec![page]).into_iter().map(Ok)).unwrap();
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["entry_count"], 0);
        assert_eq!(envelope["upstream"]["complete"], false);
        assert_eq!(
            envelope["upstream_evidence"]["fallback_reason"],
            "authentication_refused"
        );
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
            let detail =
                parse_detail_input(&format!(r#"{{"token":{token_json},"id":41}}"#)).unwrap();
            let entry = format!(
                r#"{{"id":41,"title":{title},"content":"ordinary","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}}"#
            );
            let list_body = format!(r#"{{"success":true,"data":{{"data":[{entry}]}}}}"#);
            let original = response(
                &list_url(20, 1).unwrap(),
                list_body.as_bytes(),
                Some("application/json"),
            );
            let facts = analyze_body(&original.body, token);
            let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
            let envelope = build_list_envelope(&request, (vec![page]).into_iter().map(Ok)).unwrap();
            assert_eq!(
                envelope["result"], "degraded",
                "token={token} title={title}"
            );
            assert_eq!(envelope["entry_count"], 0);
            assert_eq!(
                envelope["upstream_evidence"]["fallback_reason"],
                "credential_echo"
            );
            assert!(
                envelope["upstream_evidence"]
                    .get("raw_response_base64")
                    .is_none()
            );

            let detail_body = format!(r#"{{"success":true,"data":{entry}}}"#);
            let original = response(
                &detail_url(41).unwrap(),
                detail_body.as_bytes(),
                Some("application/json"),
            );
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
        let envelope = build_list_envelope(&request, (vec![list]).into_iter().map(Ok)).unwrap();
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(
            envelope["upstream_evidence"]["fallback_reason"],
            "credential_echo"
        );
        assert!(
            envelope["upstream_evidence"]
                .get("raw_response_base64")
                .is_none()
        );
        let page = detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.entries.is_empty());
        let evidence = page.evidence.expect("withheld detail evidence");
        assert_eq!(evidence["fallback_reason"], "credential_echo");
        assert!(evidence.get("raw_response_base64").is_none());

        let entry = r#"{"id":41,"title":"Quiet hallway","content":"ordinary","created_at":"2026-10-20 08:30:00","publish_status_text":"s","departments":[],"appeal_reply":[]}"#;
        let list_body = format!(
            r#"{{"code":20000,"success":true,"data":{{"data":[{entry}],"current_page":1,"last_page":1,"total":1}}}}"#
        );
        let original = response(
            &list_url(20, 1).unwrap(),
            list_body.as_bytes(),
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, "abc");
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        let envelope = build_list_envelope(&request, (vec![page]).into_iter().map(Ok)).unwrap();
        assert_eq!(envelope["result"], "entries");
        assert_eq!(envelope["entries"][0]["title"], "Quiet hallway");
        assert!(envelope["upstream_evidence"].is_null());

        let detail_body = format!(r#"{{"code":20000,"success":true,"data":{entry}}}"#);
        let original = response(
            &detail_url(41).unwrap(),
            detail_body.as_bytes(),
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, "abc");
        let page = detail_page(&detail, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.evidence.is_none());
        assert_eq!(page.entries[0]["title"], "Quiet hallway");
    }

    #[test]
    fn encoded_submitted_tokens_never_reach_listing_or_raw_fallback() {
        let url = list_url(20, 1).unwrap();
        let request = list_request(20);
        for token in ["opaque-token-value", "abc_123"] {
            let padded = STANDARD.encode(token);
            let unpadded = padded.trim_end_matches('=').to_owned();
            for encoded in [&padded, &unpadded] {
                let body = format!(
                    r#"{{"success":false,"message":"\u{:04x}{}"}}"#,
                    encoded.as_bytes()[0],
                    &encoded[1..]
                );
                let original = response(&url, body.as_bytes(), Some("application/json"));
                let facts = analyze_body(&original.body, token);
                assert!(facts.token_echo);
                let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
                assert!(page.entries.is_empty());
                let evidence = page.evidence.as_ref().unwrap();
                assert_eq!(evidence["fallback_reason"], "credential_echo");
                assert!(evidence.get("raw_response_base64").is_none());
                assert!(
                    !serde_json::to_string(evidence)
                        .unwrap()
                        .contains(encoded.as_str())
                );
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
            let envelope = build_list_envelope(&request, (vec![page]).into_iter().map(Ok)).unwrap();
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
    fn a_newly_issued_cookie_value_is_not_projected_when_echoed() {
        // A response may issue a fresh session cookie and echo its value in
        // the body. That value is session material, so it must be treated as
        // an echo and never reach a projection or a raw-evidence fallback.
        // The guard reviews the raw header map: `collect_headers` never
        // retains Set-Cookie, so a post-collection screening cannot work.
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=new-private-value; Path=/".parse().unwrap(),
        );
        let issued = IssuedCookies::review(&raw).unwrap();
        assert!(!issued.is_empty());
        assert_eq!(
            collect_headers(&raw)
                .unwrap()
                .keys()
                .filter(|name| name.eq_ignore_ascii_case("set-cookie"))
                .count(),
            0,
            "collection discards the header the guard reviewed"
        );
        assert!(issued.carries(br#"{"success":true,"value":"sid=new-private-value"}"#));
        assert!(issued.carries(br#"{"success":true,"value":"new-private-value"}"#));
        // The reversible spellings of an issued value are credential
        // carriers too: base64, percent-decoded and JSON-escaped echoes are
        // all withheld.
        assert!(issued.carries(br#"{"value":"bmV3LXByaXZhdGUtdmFsdWU"}"#));
        assert!(issued.carries(br#"{"value":"new%2Dprivate%2Dvalue"}"#));
        let quoted_cookie = br#"{"value":"quoted-private-value"}"#;
        let mut quoted_raw = reqwest::header::HeaderMap::new();
        quoted_raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=\"quoted-private-value\"; Path=/".parse().unwrap(),
        );
        let quoted = IssuedCookies::review(&quoted_raw).unwrap();
        assert!(quoted.carries(quoted_cookie));
        assert!(quoted.carries(br#"{"value":"\"quoted-private-value\""}"#));
        let ordinary = br#"{"success":true,"value":"unrelated"}"#;
        assert!(!issued.carries(ordinary));
        // An ordinary body carrying an authentication cookie echo is a
        // credential echo of the session material, not a business success.
        let facts = analyze_authenticated_body(
            br#"{"success":true,"value":"new-private-value"}"#,
            "synthetic-bearer",
            Some(&|bytes| issued.carries(bytes)),
        );
        assert!(facts.token_echo);
        assert!(!facts.session_denied);
        let facts = analyze_authenticated_body(
            br#"{"success":true,"value":"unrelated"}"#,
            "synthetic-bearer",
            Some(&|bytes| issued.carries(bytes)),
        );
        assert!(!facts.token_echo);
    }

    #[test]
    fn unreviewable_or_bounded_cookie_issuance_refuses_the_response() {
        // The guard may never screen a subset: a Set-Cookie that cannot be
        // parsed on its own terms refuses the whole response, including a
        // missing '=', an empty name, non-UTF-8 bytes and ambiguous quoting.
        for header in [
            "no-equals-sign",
            "=orphaned-value; Path=/",
            "invalid name=private; Path=/",
            "sid=first,other=second; Path=/",
            "sid=\"ambiguous value\"; Path=/",
            "sid=\"unbalanced; Path=/",
            "sid=va\"l\"ue; Path=/",
        ] {
            let mut raw = reqwest::header::HeaderMap::new();
            raw.insert(reqwest::header::SET_COOKIE, header.parse().unwrap());
            // `IssuedCookies` deliberately has no Debug: formatting a guard
            // must never expose the secrets it retains.
            let error = IssuedCookies::review(&raw)
                .err()
                .expect("an unparseable cookie must refuse");
            assert_eq!(error.code, "invalid_headers", "{header}");
        }
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_bytes(b"sid=n\x80nutf8; Path=/").unwrap(),
        );
        let error = IssuedCookies::review(&raw)
            .err()
            .expect("non-UTF-8 cookie material must refuse");
        assert_eq!(error.code, "invalid_headers");
        // The credential history is bounded: more than the admitted values
        // or bytes refuses rather than evicting an older secret.
        let mut issued = IssuedCookies::default();
        for index in 0..MAX_ISSUED_COOKIE_VALUES {
            let mut raw = reqwest::header::HeaderMap::new();
            raw.insert(
                reqwest::header::SET_COOKIE,
                format!("sid{index}=private-issued-value-{index}")
                    .parse()
                    .unwrap(),
            );
            issued.absorb(&raw).unwrap();
        }
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=one-too-many".parse().unwrap(),
        );
        let error = issued
            .absorb(&raw)
            .err()
            .expect("the invocation-wide value bound must refuse");
        assert_eq!(error.code, "invalid_headers");
        assert!(
            issued.carries(b"private-issued-value-0"),
            "bound exhaustion must not evict old values"
        );
        let mut raw = reqwest::header::HeaderMap::new();
        for _ in 0..9 {
            raw.append(
                reqwest::header::SET_COOKIE,
                format!("sid={}", "v".repeat(8190)).parse().unwrap(),
            );
        }
        let error = IssuedCookies::review(&raw)
            .err()
            .expect("the byte bound must refuse");
        assert_eq!(error.code, "invalid_headers");
        // An empty value is a deletion, not a transmitting secret: it is
        // admitted without joining the guard, and a mixed response still
        // screens the remaining issued value.
        let mut raw = reqwest::header::HeaderMap::new();
        raw.append(
            reqwest::header::SET_COOKIE,
            "gone=; Path=/; Max-Age=0".parse().unwrap(),
        );
        raw.append(
            reqwest::header::SET_COOKIE,
            "empty=\"\"; Path=/".parse().unwrap(),
        );
        raw.append(
            reqwest::header::SET_COOKIE,
            "sid=kept-private-value; Path=/".parse().unwrap(),
        );
        let issued = IssuedCookies::review(&raw).unwrap();
        assert_eq!(issued.values.len(), 1);
        assert!(issued.carries(br#"{"value":"kept-private-value"}"#));
        assert!(!issued.carries(br#"{"value":""}"#));
    }

    #[test]
    fn invocation_cookie_guard_screens_cached_pages_and_mime() {
        // A cached page never carries Set-Cookie, so only the invocation's
        // accumulated guard can withhold a cached body or MIME that echoes a
        // value issued by an earlier response of the same invocation.
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-cached-guard-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        let mut request = list_request(2);
        request.max_pages = 2;
        let first_url = list_url(2, 1).unwrap();
        cache
            .save(
                &response(
                    &first_url,
                    &source_page(1, 2, 3, &[41, 42]),
                    Some("application/json"),
                ),
                &ChallengeAssessment::Clear,
            )
            .unwrap();
        let second_url = list_url(2, 2).unwrap();
        let mut document: Value = serde_json::from_slice(&source_page(2, 2, 3, &[43])).unwrap();
        document["data"]["data"][0]["content"] = json!("cached-page-private");
        let body = serde_json::to_vec(&document).unwrap();
        let second = response(&second_url, &body, Some("application/json"));
        cache.save(&second, &ChallengeAssessment::Clear).unwrap();

        let mut issued = IssuedCookies::default();
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=cached-page-private; Path=/; Secure".parse().unwrap(),
        );
        issued.absorb(&raw).unwrap();
        let envelope = list_with_cache(&request, &cache, false, &mut issued).unwrap();
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(
            envelope["upstream_evidence"]["fallback_reason"],
            "credential_echo"
        );
        assert!(
            envelope["upstream_evidence"]
                .get("raw_response_base64")
                .is_none()
        );
        // The already-admitted safe page is preserved; the echoed page is not.
        assert_eq!(envelope["entry_count"], 2);
        assert!(!envelope.to_string().contains("cached-page-private"));
        assert!(
            cache.load(&second_url).unwrap().is_none(),
            "an echoed cached body is evicted"
        );

        // Ordinary control: without the issued secret in this invocation's
        // guard, the very same cached pages project normally.
        cache.save(&second, &ChallengeAssessment::Clear).unwrap();
        let control =
            list_with_cache(&request, &cache, false, &mut IssuedCookies::default()).unwrap();
        assert_eq!(control["result"], "entries");
        assert_eq!(control["entry_count"], 3);
        assert_eq!(control["upstream"]["complete"], true);

        // A cached Content-Type that echoes an invocation-issued value is
        // withheld from page metadata and evidence alike.
        let mime_url = list_url(2, 9).unwrap();
        let stored = response(
            &mime_url,
            &source_page(9, 9, 1, &[50]),
            Some("application/json; profile=\"mime-cached-private\""),
        );
        cache.save(&stored, &ChallengeAssessment::Clear).unwrap();
        let mut issued = IssuedCookies::default();
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=mime-cached-private; Path=/; Secure".parse().unwrap(),
        );
        issued.absorb(&raw).unwrap();
        let outcome = cache
            .get(
                &mime_url,
                request.token.as_str(),
                false,
                false,
                &mut issued,
                |saved, challenge, facts| {
                    assert!(facts.content_type_echo);
                    Ok::<PageOutcome, Error>(list_page(&request, saved, challenge, facts))
                },
            )
            .unwrap();
        assert!(outcome.meta["content_type"].is_null());
        assert_eq!(outcome.meta["content_type_parameters_withheld"], true);
        let evidence = outcome.evidence.expect("MIME echo evidence");
        assert_eq!(evidence["fallback_reason"], "credential_echo");
        assert!(evidence["content_type"].is_null());
        assert!(evidence.get("raw_response_base64").is_none());
        assert!(
            !serde_json::to_string(&outcome.meta)
                .unwrap()
                .contains("mime-cached-private")
        );
        assert!(cache.load(&mime_url).unwrap().is_none());
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovered_fallback_literals_recurse_into_embedded_documents() {
        // A non-JSON body has no parsed document, so its raw string literals
        // are the complete evidence. A recovered literal can itself be an
        // embedded document: screening only its decoded text once would miss
        // a secret hidden behind a second layer of JSON escaping, and the raw
        // base64 fallback would then export it.
        let url = list_url(20, 1).unwrap();
        let request = list_request(20);
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=secret; Path=/".parse().unwrap(),
        );
        let issued = IssuedCookies::review(&raw).unwrap();
        let inner = r#"{"note":"secr\u0065t"}"#;
        for (name, body) in [
            (
                "one-layer",
                format!("leading {} trailing", serde_json::to_string(inner).unwrap()),
            ),
            (
                "two-layers",
                format!(
                    "leading {} trailing",
                    serde_json::to_string(&serde_json::to_string(inner).unwrap()).unwrap()
                ),
            ),
        ] {
            let original = response(&url, body.as_bytes(), Some("text/plain"));
            let facts = screened_body_facts(&original, "synthetic-token", &issued, None);
            assert!(facts.document.is_none(), "{name}");
            assert!(
                facts.token_echo,
                "{name}: embedded escaping must not hide an issued value"
            );
            assert!(!facts.inspection_incomplete, "{name}");
            let outcome = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
            let evidence = outcome.evidence.expect("withheld fallback evidence");
            assert_eq!(evidence["fallback_reason"], "credential_echo", "{name}");
            assert!(evidence.get("raw_response_base64").is_none(), "{name}");
            let projected = serde_json::to_string(&evidence).unwrap()
                + &serde_json::to_string(&outcome.meta).unwrap();
            assert!(!projected.contains("secret"), "{name}");
            assert!(
                !projected.contains(STANDARD.encode(body.as_bytes()).as_str()),
                "{name}"
            );
        }

        // The same recursion protects the submitted bearer token and the
        // sign-on authentication material, not just issued cookie values.
        let bearer_body = format!(
            "leading {} trailing",
            serde_json::to_string(r#"{"note":"synthetic-tok\u0065n"}"#).unwrap()
        );
        let bearer = response(&url, bearer_body.as_bytes(), Some("text/plain"));
        let facts =
            screened_body_facts(&bearer, "synthetic-token", &IssuedCookies::default(), None);
        assert!(
            facts.token_echo,
            "an embedded escaped bearer token is withheld"
        );
        let auth_body = format!(
            "leading {} trailing",
            serde_json::to_string(r#"{"note":"auth-priv\u0061te"}"#).unwrap()
        );
        let auth = response(&url, auth_body.as_bytes(), Some("text/plain"));
        let authentication = |bytes: &[u8]| net::carries_secret(bytes, "auth-private");
        let facts = screened_body_facts(
            &auth,
            "synthetic-token",
            &IssuedCookies::default(),
            Some(&authentication),
        );
        assert!(
            facts.token_echo,
            "an embedded escaped authentication value is withheld"
        );

        // Ordinary control: the same recovered-literal shape without any
        // guarded secret keeps its admissible raw fallback.
        let control_body = format!(
            "leading {} trailing",
            serde_json::to_string(r#"{"note":"ordinary"}"#).unwrap()
        );
        let control = response(&url, control_body.as_bytes(), Some("text/plain"));
        let facts = screened_body_facts(&control, "synthetic-token", &issued, None);
        assert!(!facts.token_echo);
        assert!(!facts.inspection_incomplete);
        let outcome = list_page(&request, &control, &ChallengeAssessment::Clear, &facts);
        let evidence = outcome.evidence.expect("ordinary fallback evidence");
        assert_eq!(
            evidence["raw_response_base64"],
            STANDARD.encode(control_body.as_bytes())
        );

        // The embedded-document budget fails closed: a literal nested beyond
        // the reviewed depth is unreviewed, never an unscreened export.
        let mut inspection = token_inspection("synthetic-token");
        inspection.scan_decoded = true;
        inspection.inspect("{\"note\":\"secret\"}", 32, true);
        assert!(inspection.incomplete);
        assert!(!inspection.echo);
    }

    #[test]
    fn recovered_fallback_container_exhaustion_is_unreviewed_not_exportable() {
        let url = list_url(20, 1).unwrap();
        let request = list_request(20);
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=secret; Path=/".parse().unwrap(),
        );
        let issued = IssuedCookies::review(&raw).unwrap();
        for (kind, open, close) in [("array", "[", "]"), ("object", "{\"note\":", "}")] {
            for (name, depth, leaf, unreviewed, echoed) in [
                ("over-limit", 129, r#""secr\u0065t""#, true, false),
                ("ordinary-boundary", 127, r#""ordinary""#, false, false),
                ("echo-boundary", 127, r#""secr\u0065t""#, false, true),
            ] {
                // This is one JSON string literal inside non-JSON prose, not
                // a complete JSON body. Inspecting the recovered literal
                // reaches the decoder's container limit before its escaped
                // credential, so failure must retain incomplete provenance.
                let inner = format!("{}{}{}", open.repeat(depth), leaf, close.repeat(depth));
                let body = format!("prefix {} suffix", serde_json::to_string(&inner).unwrap());
                let original = response(&url, body.as_bytes(), Some("text/plain"));
                let facts = screened_body_facts(&original, "synthetic-token", &issued, None);
                assert!(facts.document.is_none(), "{kind}/{name}");
                assert_eq!(facts.inspection_incomplete, unreviewed, "{kind}/{name}");
                assert_eq!(facts.token_echo, echoed, "{kind}/{name}");
                let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
                let output = build_list_envelope(&request, [Ok(page)]).unwrap();
                let evidence = &output["upstream_evidence"];
                assert_eq!(output["result"], "degraded", "{kind}/{name}");
                if unreviewed || echoed {
                    assert_eq!(
                        evidence["fallback_reason"],
                        if unreviewed {
                            "inspection_unreviewed"
                        } else {
                            "credential_echo"
                        },
                        "{kind}/{name}"
                    );
                    assert_eq!(
                        evidence["evidence_kind"], "upstream_http_metadata",
                        "{kind}/{name}"
                    );
                    assert!(
                        evidence.get("raw_response_base64").is_none(),
                        "{kind}/{name}"
                    );
                    assert!(!output.to_string().contains("secret"), "{kind}/{name}");
                } else {
                    // Preserve the existing decoder budget and ordinary
                    // non-JSON fallback: 127 enclosing containers may still
                    // hold an admissible scalar rather than being refused.
                    assert_eq!(
                        evidence["fallback_reason"], "unexpected_content",
                        "{kind}/{name}"
                    );
                    assert_eq!(
                        evidence["raw_response_base64"],
                        STANDARD.encode(body.as_bytes()),
                        "{kind}/{name}"
                    );
                }
            }
        }
    }

    #[test]
    fn cookie_issuing_originals_are_projected_but_never_cached() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-cookie-admission-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
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
            let denied =
                body == "{\"success\":false,\"message\":\"未登录\",\"value\":\"q\"}".as_bytes();
            assert_eq!(facts.session_denied, denied);
            // A session cookie is session material, so such an original never
            // reaches the replayable cache. The business body itself is still
            // read, because the caller authenticates with its own bearer
            // token and any credential echo is screened separately.
            let projected = admit_response(
                &cache,
                &original,
                &ChallengeAssessment::Clear,
                &facts,
                net::issues_session_cookie(&headers),
                |_, _, _| -> Result<(), Error> { Ok(()) },
            );
            assert!(projected.is_ok());
            assert!(cache.load(&url).unwrap().is_none());
            assert_eq!(facts.session_denied, denied);
        }
        // A body that echoes the submitted bearer token is never cached,
        // whatever the headers say. The page layer refuses it separately.
        let echo = response(
            &url,
            br#"{"success":true,"value":"synthetic-bearer"}"#,
            Some("application/json"),
        );
        let echo_facts = analyze_body(&echo.body, "synthetic-bearer");
        assert!(echo_facts.token_echo);
        admit_response(
            &cache,
            &echo,
            &ChallengeAssessment::Clear,
            &echo_facts,
            net::issues_session_cookie(&headers),
            |_, _, _| -> Result<(), Error> { Ok(()) },
        )
        .unwrap();
        assert!(cache.load(&url).unwrap().is_none());
        let original = response(
            &url,
            br#"{"success":true,"data":[]}"#,
            Some("application/json"),
        );
        let facts = analyze_body(&original.body, "synthetic-bearer");
        let length = admit_response(
            &cache,
            &original,
            &ChallengeAssessment::Clear,
            &facts,
            net::issues_session_cookie(&reqwest::header::HeaderMap::new()),
            |response, _, _| Ok(response.body.len()),
        )
        .unwrap();
        assert_eq!(length, original.body.len());
        assert!(cache.load(&url).unwrap().is_some());
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_cache_is_preserved_but_not_published_without_cookie_admission() {
        for version in [2, 3] {
            for rejected in [false, true] {
                let root = std::env::temp_dir().join(format!(
                    "buaa-ihome-legacy-cookie-{}-{}",
                    std::process::id(),
                    SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
                ));
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .unwrap();
                let directory = root.join("cache");
                let governor_directory = root.join("governor");
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&directory)
                    .unwrap();
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&governor_directory)
                    .unwrap();
                let cache = ResponseCache {
                    directory: governor::open_directory(&directory, false, true).unwrap(),
                };
                let url = list_url(20, 1).unwrap();
                let mut original = response(
                    &url,
                    br#"{"name":"opaque-short"}"#,
                    Some("application/json"),
                );
                if rejected {
                    original.status = 403;
                }
                cache.save(&original, &ChallengeAssessment::Clear).unwrap();
                let path = directory.join(ResponseCache::name(&url));
                let mut legacy: Cached =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                legacy.version = version;
                let bytes = serde_json::to_vec(&legacy).unwrap();
                std::fs::write(&path, &bytes).unwrap();
                let error = cache
                    .get(
                        &url,
                        "different-submitted-token",
                        false,
                        false,
                        &mut IssuedCookies::default(),
                        |_, _, _| -> Result<(), Error> {
                            panic!("unreviewed legacy body reached output")
                        },
                    )
                    .unwrap_err();
                assert_eq!(
                    error.code,
                    if rejected {
                        "safety_latched"
                    } else {
                        "cached_response_unreviewed"
                    }
                );
                assert!(!error.message.contains("opaque-short"));
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                let governor = Governor::isolated_for_test(&governor_directory).unwrap();
                assert_eq!(governor.status().unwrap().safety_latched, false);
                drop(governor);
                drop(cache);
                std::fs::remove_dir_all(root).unwrap();
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
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let cache_directory = root.join("cache");
        let governor_directory = root.join("governor");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&cache_directory)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&governor_directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        // A cached HTTP 403 with an ordinary JSON body has no challenge
        // assessment, so it used to be replayed without any safety
        // observation at all.
        let mut original = response(
            &url,
            br#"{"message":"forbidden"}"#,
            Some("application/json"),
        );
        original.status = 403;
        cache.save(&original, &ChallengeAssessment::Clear).unwrap();
        let error = cache
            .get(
                &url,
                "synthetic-token-value",
                false,
                false,
                &mut IssuedCookies::default(),
                |_, _, _| Ok::<(), Error>(()),
            )
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
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let cache_directory = root.join("cache");
        let governor_directory = root.join("governor");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&cache_directory)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&governor_directory)
            .unwrap();
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
            .get(
                &url,
                "synthetic-token-value",
                false,
                false,
                &mut IssuedCookies::default(),
                |_, _, _| Ok::<(), Error>(()),
            )
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
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        let original = response(
            &url,
            br#"{"message":"opaque-token-value"}"#,
            Some("application/json"),
        );
        cache.save(&original, &ChallengeAssessment::Clear).unwrap();
        let outcome = cache
            .get(
                &url,
                "opaque-token-value",
                false,
                false,
                &mut IssuedCookies::default(),
                |response, _, facts| {
                    assert!(facts.token_echo);
                    assert!(!response.body.is_empty());
                    Ok::<(), Error>(())
                },
            )
            .unwrap();
        assert_eq!(outcome, ());
        // The echoed body is not kept on disk.
        assert!(cache.load(&url).unwrap().is_none());
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn an_incomplete_traversal_keeps_the_admitted_pages_and_advances_no_cursor() {
        let request = list_request(2);
        let page = source_outcome(&request, 1, &source_page(1, 2, 3, &[41, 42]));
        let envelope = build_list_envelope(
            &request,
            [
                Ok(page),
                Err(Error::new("offline_miss", "synthetic missing page")),
            ],
        )
        .unwrap();
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
        let url = list_url(20, 1).unwrap();
        for (mime, body) in [
            (
                "application/json",
                br#"{"redirect":"/web/?token=synthetic-secret"}"#.as_slice(),
            ),
            (
                "application/json",
                br#"{"payload":"\"Bearer synthetic-secret\""}"#.as_slice(),
            ),
            (
                "application/json",
                br#"{"url":"//files.invalid/?secret=synthetic-secret"}"#.as_slice(),
            ),
            ("text/plain", br#""Bearer synthetic-secret""#.as_slice()),
            (
                "text/html; charset=UTF-8",
                b"Sign in<input name=\"token\" value=\"synthetic-secret\">".as_slice(),
            ),
        ] {
            let original = response(&url, body, Some(mime));
            let found = evidence(
                FallbackReason::UpstreamShape,
                &original,
                "synthetic-token-value",
            );
            assert!(found.get("raw_response_base64").is_none());
            assert_eq!(found["evidence_kind"], "upstream_http_metadata");
            assert_eq!(found["sha256"], sha256(body));
        }
        let ordinary = br#"{"message":"maintenance","count":2}"#;
        let original = response(&url, ordinary, Some("application/json"));
        assert_eq!(
            evidence(
                FallbackReason::UpstreamShape,
                &original,
                "synthetic-token-value"
            )["raw_response_base64"],
            STANDARD.encode(ordinary)
        );
        let plain = b"ordinary notice";
        let original = response(&url, plain, Some("text/plain"));
        assert_eq!(
            evidence(
                FallbackReason::UpstreamParse,
                &original,
                "synthetic-token-value"
            )["raw_response_base64"],
            STANDARD.encode(plain)
        );
        let html = b"<p>ordinary notice</p>";
        let original = response(&url, html, Some("text/html"));
        assert_eq!(
            evidence(
                FallbackReason::UpstreamParse,
                &original,
                "synthetic-token-value"
            )["raw_response_base64"],
            STANDARD.encode(html)
        );
    }

    #[test]
    fn all_retry_after_fields_survive_original_lease_body_failure() {
        let root = std::env::temp_dir().join(format!(
            "buaa-ihome-headers-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let governor = Governor::isolated_for_test(&root.join("shared")).unwrap();
        let mut lease = governor
            .try_acquire(governor::RequestKind::Interactive)
            .unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "retry-after",
            reqwest::header::HeaderValue::from_static("60"),
        );
        headers.append(
            "retry-after",
            reqwest::header::HeaderValue::from_static("7200"),
        );
        headers.append(
            "retry-after",
            reqwest::header::HeaderValue::from_static("invalid"),
        );
        observe_response_headers(&mut lease, 429, &headers, true).unwrap();
        lease
            .finish(Outcome::Http {
                status: 429,
                retry_after: Some("60"),
                challenge: false,
                network_failure: true,
            })
            .unwrap();
        let state = governor.status().unwrap();
        assert!(state.cooldown_wait.as_secs() > 7100);
        assert!(!state.safety_latched);
        assert_eq!(state.consecutive_network_failures, 1);
        drop(governor);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_content_types_never_establish_clear_body_admission() {
        for types in [
            ["application/json", "text/html"],
            ["text/html", "application/json"],
            ["text/plain", "text/plain"],
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            for value in types {
                headers.append(
                    "content-type",
                    reqwest::header::HeaderValue::from_str(value).unwrap(),
                );
            }
            let collected = collect_headers(&headers).unwrap();
            let assessment = assess_response_body(
                br#"{"success":false}"#,
                collected.get("content-type").map(String::as_str),
                true,
            );
            assert!(matches!(assessment, ChallengeAssessment::Unreviewed));
            assert!(collected["content-type"].contains(", "));
        }
        assert!(matches!(
            assess_response_body(br#"{"success":false}"#, Some("application/json"), true),
            ChallengeAssessment::Clear
        ));
    }

    #[test]
    fn cached_confirmed_challenge_refuses_without_touching_production() {
        let root = std::env::temp_dir().join(format!(
            "buaa-ihome-marker-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let cache_directory = root.join("cache");
        let governor_directory = root.join("governor");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&cache_directory)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&governor_directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        let body = b"<html>cached refusal</html>";
        let original = response(&url, body, Some("text/html"));
        cache
            .save(&original, &ChallengeAssessment::Detected)
            .unwrap();
        // A cache hit on a confirmed challenge refuses without any request.
        let error = cache
            .get(
                &url,
                "synthetic-token",
                false,
                false,
                &mut IssuedCookies::default(),
                |_, _challenge, _facts| Ok::<(), Error>(()),
            )
            .unwrap_err();
        assert_eq!(error.code, "safety_latched");
        let governor = Governor::isolated_for_test(&governor_directory).unwrap();
        assert!(!governor.status().unwrap().safety_latched);
        drop(cache);
        drop(governor);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cache_race_under_a_held_lease_settles_the_same_lock() {
        let root = std::env::temp_dir().join(format!(
            "buaa-ihome-race-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let cache_directory = root.join("cache");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&cache_directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        let body = b"<html>cached refusal</html>";
        let original = response(&url, body, Some("text/html"));
        cache
            .save(&original, &ChallengeAssessment::Detected)
            .unwrap();
        let governor = Governor::isolated_for_test(&root.join("shared")).unwrap();
        let transport = Transport::open_isolated(governor).unwrap();
        let outcome = transport.fetch(
            &cache,
            &url,
            "synthetic-token",
            false,
            &mut IssuedCookies::default(),
            |_, challenge, _facts| {
                assert!(matches!(challenge, ChallengeAssessment::Detected));
                Ok::<(), Error>(())
            },
        );
        // The cache race settles the held lease without sending a request, so
        // no network access is possible in this regression.
        assert!(outcome.is_ok());
        let status = transport.governor.status().unwrap();
        assert!(!status.safety_latched);
        drop(transport);
        drop(cache);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn credential_json_is_withheld_without_collapsing_duplicate_or_escaped_keys() {
        let url = list_url(20, 1).unwrap();
        for body in [
            br#"{"token":"synthetic-secret","password":"synthetic-password"}"#.as_slice(),
            br#"{"outer":[{"to\u006ben":"synthetic-secret"}]}"#.as_slice(),
            br#"{"outer":{"token":"synthetic-secret"},"outer":{"message":"safe"}}"#.as_slice(),
            br#"{"nested":"{\"cookie\":\"synthetic-secret\"}"}"#.as_slice(),
            br#"{"link":"https://files.example.invalid/a?access%5Ftoken=synthetic-secret"}"#
                .as_slice(),
        ] {
            let original = response(&url, body, Some("application/json"));
            let found = evidence(
                FallbackReason::UpstreamShape,
                &original,
                "synthetic-token-value",
            );
            assert!(found.get("raw_response_base64").is_none());
            assert_eq!(found["evidence_kind"], "upstream_http_metadata");
            assert_eq!(found["sha256"], sha256(body));
            assert_eq!(
                page_meta(&original, 0, "synthetic-token-value")["response_body_sha256"],
                sha256(body)
            );
        }
        let safe = br#"{"message":"ordinary server maintenance","nested":[{"code":7}]}"#;
        let original = response(&url, safe, Some("application/json"));
        assert_eq!(
            evidence(
                FallbackReason::UpstreamShape,
                &original,
                "synthetic-token-value"
            )["raw_response_base64"],
            STANDARD.encode(safe)
        );
    }

    #[test]
    fn credential_urls_are_not_projected_as_attachments() {
        let mut urls = Vec::new();
        for text in [
            "https://reader:synthetic-password@files.example.invalid/photo.jpg",
            "https://files.example.invalid/photo.jpg?access%5ftoken=synthetic-secret",
            "https://files.example.invalid/photo.jpg#token=synthetic-secret",
        ] {
            collect_declared_urls(&json!(text), &mut urls, 0);
        }
        assert!(urls.is_empty());
        collect_declared_urls(
            &json!("https://files.example.invalid/photo.jpg?size=large"),
            &mut urls,
            0,
        );
        assert_eq!(
            urls,
            vec!["https://files.example.invalid/photo.jpg?size=large"]
        );
    }

    #[test]
    fn cached_private_originals_keep_hashes_without_exporting_credentials_or_mime_parameters() {
        let directory = std::env::temp_dir().join(format!(
            "buaa-ihome-private-fixture-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        let url = list_url(20, 1).unwrap();
        let body = br#"{"nested":{"password":"synthetic-secret"}}"#;
        let original = response(
            &url,
            body,
            Some("application/json; sessionid=synthetic-secret"),
        );
        cache.save(&original, &ChallengeAssessment::Clear).unwrap();
        let (saved, assessment) = cache.load(&url).unwrap().unwrap();
        assert!(matches!(assessment, ChallengeAssessment::Clear));
        assert_eq!(saved.body, body);
        assert_eq!(
            saved.headers["content-type"],
            "application/json; sessionid=synthetic-secret"
        );
        let found = evidence(
            FallbackReason::UpstreamShape,
            &saved,
            "synthetic-token-value",
        );
        assert!(found.get("raw_response_base64").is_none());
        assert_eq!(found["content_type"], "application/json");
        assert_eq!(found["content_type_parameters_withheld"], true);
        assert_eq!(found["sha256"], sha256(body));
        assert_eq!(
            page_meta(&saved, 0, "synthetic-token-value")["cache_status"],
            "hit"
        );
        assert!(
            !page_meta(&saved, 0, "synthetic-token-value")
                .to_string()
                .contains("synthetic-secret")
        );
        drop(cache);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unreviewed_challenge_is_not_a_captcha_claim_and_withholds_raw_body() {
        let url = list_url(20, 1).unwrap();
        let original = response(
            &url,
            b"<html>private-token</html>",
            Some("application/xhtml+xml"),
        );
        let assessment = assess_challenge_body(&original.body, Some("application/xhtml+xml"), true);
        let reason = response_refusal(&original, &assessment).unwrap();
        assert_eq!(reason, FallbackReason::ChallengeUnreviewed);
        let value = evidence(reason, &original, "synthetic-token-value");
        assert_eq!(value["fallback_reason"], "challenge_unreviewed");
        assert!(value.get("raw_response_base64").is_none());
        assert_eq!(value["sha256"], sha256(&original.body));
        assert!(!matches!(assessment, ChallengeAssessment::Detected));
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
        let body = br#"{"code":20000,"success":true,"data":{"data":[{"id":"not-a-number"}]}}"#;
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
        assert_eq!(
            compare_timestamps(&fractional, &zoned),
            Some(Ordering::Greater)
        );
        assert!(parse_timestamp("not a timestamp").is_none());
        assert!(parse_timestamp("2026-10-20").is_none());
        assert!(parse_timestamp("2026-02-30 08:00:00").is_none());
    }

    #[test]
    fn a_credential_bearing_content_type_is_withheld_in_list_detail_and_cache_replay() {
        let page_url = list_url(20, 1).unwrap();
        let entry_url = detail_url(41).unwrap();
        let token = "synthetic-bearer";
        let body = br#"{"code":20000,"success":true,"data":{"data":[],"current_page":1,"last_page":1,"total":0,"notice":"ordinary maintenance"}}"#;
        let list = ListRequest {
            token: Zeroizing::new(token.to_owned()),
            token_source: None,
            limit: 20,
            page: 1,
            max_pages: 1,
            since_id: None,
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::new(),
            refresh: false,
        };
        let detail = DetailRequest {
            token: Zeroizing::new(token.to_owned()),
            token_source: None,
            id: 41,
            refresh: false,
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
                list_page(
                    &list,
                    &response(&page_url, body, Some(header)),
                    &ChallengeAssessment::Clear,
                    &facts,
                ),
                detail_page(
                    &detail,
                    &response(&entry_url, body, Some(header)),
                    &ChallengeAssessment::Clear,
                    &facts,
                ),
            ] {
                let evidence = outcome.evidence.as_ref().expect("degraded evidence");
                assert_eq!(evidence["fallback_reason"], "unexpected_content");
                assert_eq!(evidence["content_type"], Value::Null);
                assert_eq!(evidence["content_type_parameters_withheld"], true);
                assert!(!serde_json::to_string(evidence).unwrap().contains(token));
                assert!(
                    !serde_json::to_string(&outcome.meta)
                        .unwrap()
                        .contains(token)
                );
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
            "buaa-ihome-mime-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&directory, false, true).unwrap(),
        };
        let stored = response(&page_url, body, Some("application/synthetic-bearer"));
        cache.save(&stored, &ChallengeAssessment::Clear).unwrap();
        let outcome = cache
            .get(
                &page_url,
                token,
                false,
                false,
                &mut IssuedCookies::default(),
                |saved, challenge, facts| {
                    assert_eq!(saved.cache_status, CacheStatus::Hit);
                    Ok::<PageOutcome, Error>(list_page(&list, saved, challenge, facts))
                },
            )
            .unwrap();
        assert_eq!(outcome.meta["content_type"], Value::Null);
        assert_eq!(outcome.meta["content_type_parameters_withheld"], true);
        assert!(
            !serde_json::to_string(&outcome.meta)
                .unwrap()
                .contains(token)
        );
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
            let envelope = build_list_envelope(&list_request(20), (vec![PageOutcome {
                meta: page_meta(&original, 0, token),
                success: None,
                evidence: Some(found),
                entries: Vec::new(),
                pagination: None,
                source: page_source(&original),
            }]).into_iter().map(Ok)).unwrap();
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
        assert!(
            evidence(FallbackReason::UpstreamParse, &original, token)
                .get("raw_response_base64")
                .is_none()
        );
    }
}

// ---------------------------------------------------------------------------
// Reviewed session privacy regressions
// ---------------------------------------------------------------------------

/// A session read holds the operator credential for the whole request, so a
/// body that reflects it must be refused as `credential_echo` with its
/// original bytes withheld, whatever reversible spelling the upstream used.
/// Every credential here is synthetic.
#[cfg(test)]
mod ihome_review_regressions {
    use super::*;

    /// A permitted credential with a non-BMP character. Its UTF-16 surrogate
    /// pair spelling is the reviewed gap.
    const HELD_CREDENTIAL: &str = "q😀r";
    const BEARER: &str = "synthetic-token-value";

    fn review_response(url: &Url, body: &[u8], content_type: Option<&str>) -> Response {
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

    fn review_list_request() -> ListRequest {
        ListRequest {
            token: Zeroizing::new(BEARER.to_owned()),
            token_source: Some(TokenSource::RedirectFragmentToken),
            limit: 20,
            page: 1,
            max_pages: 1,
            since_id: None,
            since_time_raw: None,
            since_time: None,
            known: BTreeMap::new(),
            refresh: false,
        }
    }

    fn review_detail_request() -> DetailRequest {
        DetailRequest {
            token: Zeroizing::new(BEARER.to_owned()),
            token_source: Some(TokenSource::RedirectFragmentToken),
            id: 41,
            refresh: false,
        }
    }

    /// The extra held-credential predicate a session read applies to every
    /// response body in addition to the bearer token.
    fn holds_credential(bytes: &[u8]) -> bool {
        net::carries_secret(bytes, HELD_CREDENTIAL)
    }

    #[test]
    fn ihome_review_regression_surrogate_escaped_credential_prose_is_withheld() {
        // A complete non-JSON text/plain prose that quotes the held
        // credential as a JSON string literal spelled with UTF-16 surrogate
        // escapes. The decoded literal is the credential, so the original
        // bytes must be withheld and the refusal must be reported as
        // `credential_echo` instead of only toggling an internal flag.
        let body = br#"notice: "q\ud83d\ude00r" was recorded"#;
        let url = list_url(20, 1).unwrap();
        let original = review_response(&url, body, Some("text/plain"));
        let contains: &dyn Fn(&[u8]) -> bool = &holds_credential;
        let facts = analyze_authenticated_body(&original.body, BEARER, Some(contains));
        let request = review_list_request();
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.entries.is_empty());
        let found = page.evidence.as_ref().expect("withheld list evidence");
        assert_eq!(found["fallback_reason"], "credential_echo");
        assert_eq!(found["evidence_kind"], "upstream_http_metadata");
        assert!(
            found.get("raw_response_base64").is_none(),
            "reversible raw response leaked"
        );
        let envelope = build_list_envelope(&request, (vec![page]).into_iter().map(Ok)).unwrap();
        assert_eq!(envelope["result"], "degraded");
        assert_eq!(envelope["entry_count"], 0);
        assert_eq!(
            envelope["upstream_evidence"]["fallback_reason"],
            "credential_echo"
        );
        assert!(
            envelope["upstream_evidence"]
                .get("raw_response_base64")
                .is_none()
        );
        assert!(!serde_json::to_string(&envelope).unwrap().contains("ud83d"));
        // The detail read refuses the same body.
        let detail_request = review_detail_request();
        let detail = detail_page(
            &detail_request,
            &original,
            &ChallengeAssessment::Clear,
            &facts,
        );
        assert!(detail.entries.is_empty());
        let found = detail.evidence.as_ref().expect("withheld detail evidence");
        assert_eq!(found["fallback_reason"], "credential_echo");
        assert!(found.get("raw_response_base64").is_none());
    }

    #[test]
    fn ihome_review_regression_surrogate_escaped_credential_json_document_is_refused() {
        // The parsed-document branch decodes the surrogate pair already. The
        // held credential must be refused there too, and the parsed document
        // must never be projected.
        let body = br#"{"message":"q\ud83d\ude00r"}"#;
        let url = list_url(20, 1).unwrap();
        let original = review_response(&url, body, Some("application/json"));
        let contains: &dyn Fn(&[u8]) -> bool = &holds_credential;
        let facts = analyze_authenticated_body(&original.body, BEARER, Some(contains));
        let request = review_list_request();
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.entries.is_empty());
        let found = page.evidence.as_ref().expect("withheld evidence");
        assert_eq!(found["fallback_reason"], "credential_echo");
        assert!(found.get("raw_response_base64").is_none());
    }

    #[test]
    fn ihome_review_regression_ordinary_escaped_prose_stays_admissible() {
        // The same prose shape without the credential keeps its original
        // bytes: the decoder must not refuse every escaped literal.
        let body = br#"notice: "caf\u00e9 \ud83d\ude00" was recorded"#;
        let url = list_url(20, 1).unwrap();
        let original = review_response(&url, body, Some("text/plain"));
        let contains: &dyn Fn(&[u8]) -> bool = &holds_credential;
        let facts = analyze_authenticated_body(&original.body, BEARER, Some(contains));
        let request = review_list_request();
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.entries.is_empty());
        let found = page.evidence.as_ref().expect("fallback evidence");
        assert_eq!(found["fallback_reason"], "unexpected_content");
        assert_eq!(found["evidence_kind"], "upstream_http_body");
        assert_eq!(found["raw_response_base64"], STANDARD.encode(body));
    }

    #[test]
    fn ihome_review_regression_unpaired_surrogate_prose_stays_admissible() {
        // An unpaired high surrogate is not the credential spelling and must
        // not be combined with the text that follows it. The body stays
        // admissible and its original bytes are released.
        let body = br#"notice: "\ud83dA" was recorded"#;
        let url = list_url(20, 1).unwrap();
        let original = review_response(&url, body, Some("text/plain"));
        let contains: &dyn Fn(&[u8]) -> bool = &holds_credential;
        let facts = analyze_authenticated_body(&original.body, BEARER, Some(contains));
        let request = review_list_request();
        let page = list_page(&request, &original, &ChallengeAssessment::Clear, &facts);
        assert!(page.entries.is_empty());
        let found = page.evidence.as_ref().expect("fallback evidence");
        assert_eq!(found["fallback_reason"], "unexpected_content");
        assert_eq!(found["raw_response_base64"], STANDARD.encode(body));
    }

    // -------------------------------------------------------------------
    // Late-issued cookie consumer regression
    // -------------------------------------------------------------------
    //
    // One strict-TLS loopback stands in for `i.buaa.edu.cn` alone: an
    // ephemeral CA signs one leaf for that host, the test client pins only
    // that CA and resolves the real hostname to the loopback listener.
    // Nothing is relaxed, no campus endpoint or credential is touched.

    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslMethod, SslStream};
    use openssl::x509::X509;
    use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::os::unix::fs::DirBuilderExt as _;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as SyncOrdering};
    use std::sync::{Arc, Mutex};

    /// The one loopback request this fixture needs to classify: request
    /// line target plus the header lines, bounded well under any body an
    /// appeal read would legitimately receive.
    const MAX_LOOPBACK_REQUEST: usize = 64 * 1024;

    struct LoopbackRequest {
        target: String,
        headers: Vec<(String, String)>,
    }

    /// Ephemeral CA plus one leaf whose SAN covers only `i.buaa.edu.cn`.
    struct LoopbackPki {
        ca_pem: Vec<u8>,
        leaf_pem: Vec<u8>,
        key_pem: Vec<u8>,
    }

    fn loopback_pki() -> LoopbackPki {
        let rsa = Rsa::generate(2048).expect("rsa key");
        let key = PKey::from_rsa(rsa).expect("pkey");
        let serial = || {
            let mut serial = BigNum::new().expect("bignum");
            serial
                .rand(64, MsbOption::MAYBE_ZERO, false)
                .expect("serial");
            serial.to_asn1_integer().expect("asn1 serial")
        };
        let mut name = openssl::x509::X509NameBuilder::new().expect("ca name");
        name.append_entry_by_text("CN", "buaa-cli synthetic ihome CA")
            .expect("ca name entry");
        let name = name.build();
        let mut ca_builder = X509::builder().expect("ca builder");
        ca_builder.set_version(2).expect("version");
        ca_builder.set_serial_number(&serial()).expect("serial");
        ca_builder.set_subject_name(&name).expect("ca subject");
        ca_builder.set_issuer_name(&name).expect("ca issuer");
        ca_builder.set_pubkey(&key).expect("ca pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("not before");
        ca_builder.set_not_before(&not_before).expect("not before");
        let not_after = Asn1Time::days_from_now(1).expect("not after");
        ca_builder.set_not_after(&not_after).expect("not after");
        ca_builder
            .append_extension(BasicConstraints::new().critical().ca().build().expect("bc"))
            .expect("ca constraints");
        ca_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .expect("ca key usage"),
            )
            .expect("ca usage");
        ca_builder
            .sign(&key, MessageDigest::sha256())
            .expect("ca sign");
        let ca = ca_builder.build();

        let mut leaf_name = openssl::x509::X509NameBuilder::new().expect("leaf name");
        leaf_name
            .append_entry_by_text("CN", IHOME_HOST)
            .expect("leaf cn");
        let leaf_name = leaf_name.build();
        let mut leaf = X509::builder().expect("leaf builder");
        leaf.set_version(2).expect("version");
        leaf.set_serial_number(&serial()).expect("serial");
        leaf.set_subject_name(&leaf_name).expect("leaf subject");
        leaf.set_issuer_name(ca.subject_name()).expect("leaf issuer");
        leaf.set_pubkey(&key).expect("leaf pubkey");
        leaf.set_not_before(&not_before).expect("not before");
        leaf.set_not_after(&not_after).expect("not after");
        let san = SubjectAlternativeName::new()
            .dns(IHOME_HOST)
            .build(&leaf.x509v3_context(Some(&ca), None))
            .expect("san");
        leaf.append_extension(san).expect("leaf san");
        leaf.append_extension(BasicConstraints::new().critical().build().expect("leaf bc"))
            .expect("leaf constraints");
        leaf.sign(&key, MessageDigest::sha256()).expect("leaf sign");
        let leaf = leaf.build();
        LoopbackPki {
            ca_pem: ca.to_pem().expect("ca pem"),
            leaf_pem: leaf.to_pem().expect("leaf pem"),
            key_pem: key.private_key_to_pem_pkcs8().expect("key pem"),
        }
    }

    fn loopback_acceptor(pki: &LoopbackPki) -> Arc<SslAcceptor> {
        let mut builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("tls acceptor");
        builder
            .set_private_key(&PKey::private_key_from_pem(&pki.key_pem).expect("key"))
            .expect("acceptor key");
        builder
            .set_certificate(&X509::from_pem(&pki.leaf_pem).expect("leaf"))
            .expect("acceptor cert");
        builder
            .add_extra_chain_cert(X509::from_pem(&pki.ca_pem).expect("ca"))
            .expect("chain");
        builder.check_private_key().expect("key pair");
        Arc::new(builder.build())
    }

    /// The test client pins the ephemeral CA and resolves the real host to
    /// loopback; verification stays fully enforced.
    fn loopback_client(pki: &LoopbackPki, address: SocketAddr) -> Client {
        Client::builder()
            .user_agent("buaa-cli/0.1 ihome")
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
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .https_only(true)
            .add_root_certificate(
                reqwest::Certificate::from_pem(&pki.ca_pem).expect("pinned ca"),
            )
            .resolve(IHOME_HOST, address)
            .build()
            .expect("strict test client")
    }

    fn loopback_http_response(status: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("Connection: close\r\n\r\n");
        response.push_str(body);
        response.into_bytes()
    }

    fn read_loopback_request(stream: &mut SslStream<TcpStream>) -> Option<LoopbackRequest> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
            if bytes.len() > MAX_LOOPBACK_REQUEST {
                return None;
            }
            let read = std::io::Read::read(stream, &mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            bytes.extend_from_slice(&chunk[..read]);
        };
        let head = String::from_utf8_lossy(&bytes[..header_end]);
        let mut lines = head.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.split(' ');
        let _method = parts.next()?;
        let target = parts.next()?.to_owned();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':')?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        Some(LoopbackRequest { target, headers })
    }

    /// One bounded loopback worker: the listener polls a stop flag and each
    /// connection is served once with timeouts, so a failed test never
    /// strands a thread.
    struct IhomeLoopback {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<LoopbackRequest>>>,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl IhomeLoopback {
        fn start(
            acceptor: Arc<SslAcceptor>,
            responder: impl Fn(&LoopbackRequest) -> Vec<u8> + Send + 'static,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
            listener.set_nonblocking(true).expect("nonblocking listener");
            let address = listener.local_addr().expect("listener address");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (worker_requests, worker_stop) = (Arc::clone(&requests), Arc::clone(&stop));
            let worker = std::thread::spawn(move || {
                while !worker_stop.load(SyncOrdering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                            let mut tls = match acceptor.accept(stream) {
                                Ok(tls) => tls,
                                Err(_) => continue,
                            };
                            let Some(request) = read_loopback_request(&mut tls) else {
                                continue;
                            };
                            let response = responder(&request);
                            worker_requests.lock().expect("request log").push(request);
                            let _ = std::io::Write::write_all(&mut tls, &response);
                            let _ = tls.shutdown();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                requests,
                stop,
                worker: Some(worker),
            }
        }

        fn observed(&self) -> Vec<(String, Vec<(String, String)>)> {
            self.requests
                .lock()
                .expect("request log")
                .iter()
                .map(|request| (request.target.clone(), request.headers.clone()))
                .collect()
        }
    }

    impl Drop for IhomeLoopback {
        fn drop(&mut self) {
            self.stop.store(true, SyncOrdering::SeqCst);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    /// A fresh temporary directory removed when the test ends; created new
    /// every run so no stale state can be replayed.
    struct LoopbackDir {
        path: std::path::PathBuf,
    }

    impl Drop for LoopbackDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    static LOOPBACK_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn loopback_directory(name: &str) -> LoopbackDir {
        let path = std::env::temp_dir().join(format!(
            "buaa-ihome-loopback-{}-{name}-{}",
            std::process::id(),
            LOOPBACK_SEQUENCE.fetch_add(1, SyncOrdering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("loopback test directory");
        LoopbackDir { path }
    }

    /// One appeal-board page in the documented envelope shape.
    fn loopback_list_page(current: u32, last: u32, total: u64, id: u64, content: &str) -> String {
        serde_json::to_string(&json!({
            "code": 20000,
            "success": true,
            "data": {
                "current_page": current,
                "last_page": last,
                "total": total,
                "data": [{
                    "id": id,
                    "title": "Synthetic appeal",
                    "content": content,
                    "created_at": "2026-10-20 08:30:00",
                    "publish_status_text": "Pending",
                    "departments": [],
                    "appeal_reply": []
                }]
            }
        }))
        .expect("page body")
    }

    fn loopback_page_query(target: &str) -> String {
        Url::parse(&format!("https://{IHOME_HOST}{target}"))
            .expect("observed request target")
            .query_pairs()
            .find(|(name, _)| name == "page")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default()
    }

    #[test]
    fn ihome_review_regression_late_issued_cookie_cannot_reach_earlier_output() {
        // The invocation cookie guard only learns a value when a later
        // response's Set-Cookie issues it. An earlier page's record that
        // already carries that string is ordinary business content when it
        // was processed, but it becomes credential material the moment the
        // later response issues it: the consumer envelope must then withhold
        // it and must not report a complete traversal. The ordinary leg
        // proves the same string stays admissible when nothing issues it.
        const FUTURE: &str = "future-cookie-private";
        for (name, issue) in [("issued", true), ("ordinary", false)] {
            let first_body = loopback_list_page(1, 2, 2, 41, FUTURE);
            let second_body = loopback_list_page(2, 2, 2, 42, "Second ordinary appeal");
            let set_cookie = format!("sid={FUTURE}; Path=/api; Secure; HttpOnly");
            let pki = loopback_pki();
            let endpoint = IhomeLoopback::start(loopback_acceptor(&pki), move |request| {
                match loopback_page_query(&request.target).as_str() {
                    "1" => loopback_http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        &first_body,
                    ),
                    "2" if issue => loopback_http_response(
                        "200 OK",
                        &[
                            ("Content-Type", "application/json"),
                            ("Set-Cookie", &set_cookie),
                        ],
                        &second_body,
                    ),
                    "2" => loopback_http_response(
                        "200 OK",
                        &[("Content-Type", "application/json")],
                        &second_body,
                    ),
                    _ => loopback_http_response("404 Not Found", &[], "unexpected"),
                }
            });
            let client = loopback_client(&pki, endpoint.address);
            let cache_directory = loopback_directory(&format!("cache-{name}"));
            let governor_directory = loopback_directory(&format!("governor-{name}"));
            let governor =
                Governor::isolated_for_test(&governor_directory.path).expect("isolated governor");
            let output = list_with_test_network(
                &json!({"token": BEARER, "limit": 1, "page": 1, "max_pages": 2}).to_string(),
                &cache_directory.path,
                client,
                governor,
            )
            .expect("the bounded traversal settles normally");

            // Exactly the two documented pages were requested once each;
            // no request adopted or transmitted the issued cookie.
            let observed = endpoint.observed();
            assert_eq!(observed.len(), 2, "{name}: one request per page");
            let mut observed_pages = Vec::new();
            for (target, headers) in &observed {
                let header = |name: &str| {
                    headers
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_str())
                };
                assert!(
                    header("cookie").is_none(),
                    "{name}: no cookie adoption or transmission"
                );
                assert_eq!(
                    header("authorization"),
                    Some(format!("Bearer {BEARER}").as_str()),
                    "{name}"
                );
                observed_pages.push(loopback_page_query(target));
            }
            assert_eq!(observed_pages, ["1", "2"], "{name}");

            let cache = ResponseCache {
                directory: governor::open_directory(&cache_directory.path, false, true)
                    .expect("cache directory"),
            };
            if issue {
                // The page-2 response issued `future-cookie-private` as
                // session material, so the identical string in page-1's
                // already-collected record is a credential disclosure:
                // nothing in the consumer envelope may carry it, and the
                // traversal is never reported complete.
                assert!(
                    !output.to_string().contains(FUTURE),
                    "{name}: a late-issued credential never reaches output"
                );
                assert_ne!(
                    output["upstream"]["complete"], true,
                    "{name}: a withheld page cannot settle as complete"
                );
                assert_ne!(output["result"], "entries", "{name}");
                // The issuing response is never persisted as a replayable
                // page; the ordinary first page stays cached.
                assert!(
                    cache
                        .load(&list_url(1, 2).unwrap())
                        .expect("cache read")
                        .is_none(),
                    "{name}: the cookie-issuing response is never cached"
                );
            } else {
                // Ordinary control: the very same record content is business
                // data when no response issues it as a credential.
                assert_eq!(output["result"], "entries", "{name}");
                assert_eq!(output["entry_count"], 2, "{name}");
                assert_eq!(output["upstream"]["complete"], true, "{name}");
                assert_eq!(output["entries"][0]["content"], FUTURE, "{name}");
                assert_eq!(output["entries"][1]["id"], 42, "{name}");
                assert!(
                    cache
                        .load(&list_url(1, 2).unwrap())
                        .expect("cache read")
                        .is_some(),
                    "{name}: the ordinary response is retained"
                );
            }
        }
    }

    #[test]
    fn ihome_review_regression_unreviewable_prior_cache_keeps_fresh_publication() {
        // A pre-cookie-review cache file (version 3) refuses as
        // `cached_response_unreviewed` on read, and that policy is preserved:
        // the original bytes stay on disk. But a fresh `refresh` response that
        // issues a session cookie must still publish; the post-traversal
        // admission re-screen must skip the unreviewable prior file instead of
        // discarding the independently admitted result.
        const ISSUED: &str = "refresh-page-cookie";
        let first_body = loopback_list_page(1, 1, 1, 41, "Synthetic first appeal");
        let set_cookie = format!("sid={ISSUED}; Path=/; Secure; HttpOnly");
        let pki = loopback_pki();
        let endpoint = IhomeLoopback::start(loopback_acceptor(&pki), move |request| {
            match loopback_page_query(&request.target).as_str() {
                "1" => loopback_http_response(
                    "200 OK",
                    &[
                        ("Content-Type", "application/json"),
                        ("Set-Cookie", &set_cookie),
                    ],
                    &first_body,
                ),
                _ => loopback_http_response("404 Not Found", &[], "unexpected"),
            }
        });
        let client = loopback_client(&pki, endpoint.address);
        let cache_directory = loopback_directory("cache-refresh-legacy");
        let governor_directory = loopback_directory("governor-refresh-legacy");

        // Plant a version-3 admission for exactly this page before the
        // traversal. `cache.save` writes version 4; rewriting the version
        // field keeps every other byte of the admitted record.
        let first_url = list_url(1, 1).unwrap();
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory.path, false, true)
                .expect("cache directory"),
        };
        cache
            .save(
                &review_response(
                    &first_url,
                    loopback_list_page(1, 1, 1, 41, "Synthetic first appeal").as_bytes(),
                    Some("application/json"),
                ),
                &ChallengeAssessment::Clear,
            )
            .expect("legacy seed");
        let legacy_path = cache_directory.path.join(ResponseCache::name(&first_url));
        let mut legacy: Cached =
            serde_json::from_slice(&std::fs::read(&legacy_path).unwrap()).unwrap();
        legacy.version = 3;
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        std::fs::write(&legacy_path, &legacy_bytes).unwrap();

        let governor =
            Governor::isolated_for_test(&governor_directory.path).expect("isolated governor");
        let output = list_with_test_network(
            &json!({"token": BEARER, "limit": 1, "page": 1, "max_pages": 1, "refresh": true})
                .to_string(),
            &cache_directory.path,
            client,
            governor,
        )
        .expect("the refresh traversal settles normally");

        // The fresh response was fetched (the legacy file was bypassed by the
        // refresh), projected, and its session-cookie issuance correctly kept
        // the fresh body out of the replayable cache — but the unreviewable
        // prior file was not allowed to invalidate the result.
        assert_eq!(endpoint.observed().len(), 1);
        assert_eq!(output["result"], "entries");
        assert_eq!(output["entry_count"], 1);
        assert_eq!(output["entries"][0]["id"], 41);
        assert_eq!(output["upstream"]["complete"], true);
        assert_eq!(output["upstream_evidence"], Value::Null);

        // The unreviewable original is preserved byte-for-byte, and it still
        // refuses publication on the ordinary read path.
        assert_eq!(std::fs::read(&legacy_path).unwrap(), legacy_bytes);
        let error = cache
            .load(&first_url)
            .err()
            .expect("legacy read still refuses");
        assert_eq!(error.code, "cached_response_unreviewed");
    }

    #[test]
    fn ihome_review_regression_generated_field_name_never_withholds_a_page() {
        // `content_type` is adapter-generated envelope vocabulary, not source
        // material. An upstream-issued cookie value that collides with a
        // generated field name is still ordinary credential material for the
        // guard, but it cannot withhold a safe page, null out required
        // metadata members, or erase schema fields: only the retained source
        // bytes, headers and URL are screened.
        const KEY_COLLISION: &str = "content_type";
        let first_body = loopback_list_page(1, 2, 2, 41, "Synthetic first appeal");
        let second_body = loopback_list_page(2, 2, 2, 42, "Synthetic second appeal");
        let set_cookie = format!("sid={KEY_COLLISION}; Path=/; Secure; HttpOnly");
        let pki = loopback_pki();
        let endpoint = IhomeLoopback::start(loopback_acceptor(&pki), move |request| {
            match loopback_page_query(&request.target).as_str() {
                "1" => loopback_http_response(
                    "200 OK",
                    &[("Content-Type", "application/json")],
                    &first_body,
                ),
                "2" => loopback_http_response(
                    "200 OK",
                    &[
                        ("Content-Type", "application/json"),
                        ("Set-Cookie", &set_cookie),
                    ],
                    &second_body,
                ),
                _ => loopback_http_response("404 Not Found", &[], "unexpected"),
            }
        });
        let client = loopback_client(&pki, endpoint.address);
        let cache_directory = loopback_directory("cache-key-collision");
        let governor_directory = loopback_directory("governor-key-collision");
        let governor =
            Governor::isolated_for_test(&governor_directory.path).expect("isolated governor");
        let output = list_with_test_network(
            &json!({"token": BEARER, "limit": 1, "page": 1, "max_pages": 2}).to_string(),
            &cache_directory.path,
            client,
            governor,
        )
        .expect("the bounded traversal settles normally");

        // The generated key name is not credential evidence: both pages stay
        // published and the traversal is complete.
        assert_eq!(output["result"], "entries");
        assert_eq!(output["entry_count"], 2);
        assert_eq!(output["upstream"]["complete"], true);
        // Required metadata members keep their real values; nothing was
        // nulled or removed by the publication screen.
        for record in output["upstream"]["pages"].as_array().unwrap() {
            for key in [
                "url",
                "status",
                "content_type",
                "entry_count",
                "fetched_at_unix_ms",
                "response_body_sha256",
                "cache_status",
            ] {
                assert!(!record[key].is_null(), "missing member {key}");
            }
            assert_eq!(record["content_type"], "application/json");
            assert_eq!(record["status"], 200);
        }
        let cache = ResponseCache {
            directory: governor::open_directory(&cache_directory.path, false, true)
                .expect("cache directory"),
        };
        // The ordinary first page stays cached; the cookie-issuing second
        // page is never written.
        assert!(cache.load(&list_url(1, 1).unwrap()).unwrap().is_some());
        assert!(cache.load(&list_url(1, 2).unwrap()).unwrap().is_none());
    }

    #[test]
    fn ihome_review_regression_url_carrying_page_uses_documented_marker() {
        // `api` is a path segment of every request URL (`/api/appeal`). A
        // cookie issued as `sid=api` therefore makes the page's own request
        // URL a credential carrier: the page is withheld like any
        // credential-echo refusal, but the required `url` member must stay a
        // string — the documented `withheld` marker — with `url_withheld`
        // stating the substitution. No null, no fabricated URL, and the
        // issued value never reaches the envelope.
        let body = loopback_list_page(1, 1, 1, 41, "Synthetic appeal");
        let set_cookie = "sid=api; Path=/api; Secure; HttpOnly".to_owned();
        let pki = loopback_pki();
        let endpoint = IhomeLoopback::start(loopback_acceptor(&pki), move |request| {
            match loopback_page_query(&request.target).as_str() {
                "1" => loopback_http_response(
                    "200 OK",
                    &[
                        ("Content-Type", "application/json"),
                        ("Set-Cookie", &set_cookie),
                    ],
                    &body,
                ),
                _ => loopback_http_response("404 Not Found", &[], "unexpected"),
            }
        });
        let client = loopback_client(&pki, endpoint.address);
        let cache_directory = loopback_directory("cache-url-marker");
        let governor_directory = loopback_directory("governor-url-marker");
        let governor =
            Governor::isolated_for_test(&governor_directory.path).expect("isolated governor");
        let output = list_with_test_network(
            &json!({"token": BEARER, "limit": 1, "page": 1, "max_pages": 1}).to_string(),
            &cache_directory.path,
            client,
            governor,
        )
        .expect("the bounded traversal settles normally");

        // The page is withheld as a credential echo: no entries, no
        // completeness, evidence carries the echo reason and no raw bytes.
        assert_eq!(output["result"], "degraded");
        assert_eq!(output["entry_count"], 0);
        assert_ne!(output["upstream"]["complete"], true);
        assert_eq!(
            output["upstream_evidence"]["fallback_reason"],
            "credential_echo"
        );
        assert!(
            output["upstream_evidence"]
                .get("raw_response_base64")
                .is_none()
        );

        // The page record keeps every required `page_meta_schema` member:
        // `url` is the documented marker string with `url_withheld`, never a
        // null and never the credential-bearing request URL.
        let record = &output["upstream"]["pages"][0];
        for key in [
            "url",
            "status",
            "content_type",
            "content_type_parameters_withheld",
            "entry_count",
            "fetched_at_unix_ms",
            "response_body_sha256",
            "cache_status",
        ] {
            assert!(!record[key].is_null(), "required member {key}");
        }
        assert_eq!(record["url"], WITHHELD_URL_MARKER);
        assert_eq!(record["url_withheld"], true);
        assert!(record["url"].is_string());
        assert_eq!(record["status"], 200);
        assert_eq!(record["entry_count"], 0);

        // The issued value and the real request URL are absent from the
        // entire consumer envelope.
        let text = output.to_string();
        assert!(!text.contains("i.buaa.edu.cn"));
        assert!(!text.contains("/api/appeal"));
        assert!(!text.contains("api"));
    }
}

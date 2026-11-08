//! HTTPS-only shuttle observations and fail-closed purchase planning.
//! The published HTTP CAS service is not an authorization to downgrade transport.
//! No ticket is submitted until HTTPS authentication and order verification have
//! a documented contract. Payment, retries and captcha recognition are absent.
//! The bounded read-only schedule path reports an explicitly incomplete list
//! instead of inferring shifts or seat availability. Purchase and cancel keep
//! an explicit refusal code until exact typed intent, immutable preview and an
//! independent postcondition all exist.

use crate::governor::{FollowupError, Governor, Outcome, RequestKind, RequestLease};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use crate::net::Error;
use crate::recordings::session::{self as cas, CasService, SsoCredentials};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroizing;

const ORIGIN: &str = "https://zhihuixiaoche.buaa.edu.cn";
const LIMIT: usize = 4 * 1024 * 1024;
const AUTH_REASON: &str = "The upstream CAS service is http://zhihuixiaoche.buaa.edu.cn/wechat/CASLogin. HTTPS-equivalent CAS acceptance and an authenticated session are unverified; HTTP downgrade is prohibited.";
const PURCHASE_INTENT: &str = "purchase_shuttle_ticket";
// The only documented read-only page parameter is shifts_number; a route name
// is never translated into one. Route is therefore the exact upstream numeric
// identifier as displayed by that page.
const ROUTE_PARAMETER: &str = "shifts_number";
const AVAILABILITY_REASON: &str = "该页面未提供可解析的余票结构；不推断余票数值";
const SCHEDULE_REASON: &str = "保留的排班页面仅作为只读观察；班次与余票结构未验证，不推断余票数值";
const MUTATION_REFUSAL_CODE: &str =
    "mutation_requires_exact_typed_intent_immutable_preview_and_postcondition";
const MUTATION_REQUIRED: [&str; 3] = [
    "exact_typed_intent",
    "immutable_preview_confirmation",
    "independent_postcondition",
];

/// Rejects duplicate object members and non-object roots without losing the
/// exact scalar/array shapes needed for strict validation.
struct StrictValue(Value);
impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let value = map.next_value::<StrictValue>()?;
                    object.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(object)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> Result<Self::Value, S::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_owned())))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| StrictValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn invalid() -> Error {
    Error::new(
        "invalid_input",
        "invalid shuttle input; consult shuttle schema",
    )
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn blocked(operation: &str, reason: &str) -> Value {
    json!({"operation":operation,"status":"blocked","reason":reason})
}

fn valid_date(value: &Value) -> bool {
    value
        .get("date")
        .and_then(Value::as_str)
        .is_some_and(|date| {
            date.len() == 10
                && date.as_bytes()[4] == b'-'
                && date.as_bytes()[7] == b'-'
                && date
                    .bytes()
                    .enumerate()
                    .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
                && chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok()
        })
}

/// A route is the exact upstream numeric identifier, never a translated name.
fn valid_identifier(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_u64)
        .is_some_and(|n| n >= 1 && n <= u32::MAX as u64)
}

fn missing_purchase_preconditions(value: &Value, preview_confirmed: bool) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if value.get("intent").and_then(Value::as_str) != Some(PURCHASE_INTENT) {
        missing.push("exact_typed_intent");
    }
    if !preview_confirmed {
        missing.push("immutable_preview_confirmation");
    }
    missing.push("independent_postcondition");
    missing
}

fn sensitive_echo(bytes: &[u8]) -> bool {
    if let Ok(value) = serde_json::from_slice::<JsonPrivacy>(bytes) {
        return value.0;
    }
    sensitive_text(bytes)
}

struct JsonPrivacy(bool);
impl<'de> serde::Deserialize<'de> for JsonPrivacy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonPrivacy;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut sensitive = false;
                while let Some(key) = map.next_key::<String>()? {
                    sensitive |= sensitive_text(key.as_bytes());
                    sensitive |= map.next_value::<JsonPrivacy>()?.0;
                }
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> Result<Self::Value, S::Error> {
                let mut sensitive = false;
                while let Some(value) = seq.next_element::<JsonPrivacy>()? {
                    sensitive |= value.0;
                }
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(sensitive_text(value.as_bytes())))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn sensitive_value(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields
            .iter()
            .any(|(key, value)| sensitive_text(key.as_bytes()) || sensitive_value(value)),
        Value::Array(values) => values.iter().any(sensitive_value),
        Value::String(text) => sensitive_text(text.as_bytes()),
        _ => false,
    }
}

fn safe_content_type(content_type: Option<&str>) -> Option<&'static str> {
    match content_type?.split(';').next()?.trim() {
        value if value.eq_ignore_ascii_case("application/json") => Some("application/json"),
        value if value.eq_ignore_ascii_case("text/html") => Some("text/html"),
        value if value.eq_ignore_ascii_case("text/plain") => Some("text/plain"),
        value if value.eq_ignore_ascii_case("application/octet-stream") => {
            Some("application/octet-stream")
        }
        _ => None,
    }
}

fn sensitive_text(bytes: &[u8]) -> bool {
    const MARKERS: &[&[u8]] = &[
        b"session",
        b"cookie",
        b"token",
        b"ticket",
        b"authorization",
        b"credential",
        b"password",
        b"passwd",
        b"secret",
        b"csrf",
        b"execution",
        b"<input",
        b"<form",
        b"bearer",
        b"jwt",
        b"nonce",
        b"loginname",
        b"login_name",
        b"\\u",
        b"\\x",
        b"&#",
    ];
    MARKERS.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
    })
}

fn evidence(
    bytes: &[u8],
    content_type: Option<&str>,
    reason: &str,
    assessment: &ChallengeAssessment,
) -> Value {
    let retain = matches!(assessment, ChallengeAssessment::Clear) && !sensitive_echo(bytes);
    json!({"body_base64":retain.then(||STANDARD.encode(bytes)),"content_type":safe_content_type(content_type),
        "byte_count":bytes.len(),"sha256":digest(bytes),"fallback_reason":reason,
        "raw_withheld":!retain,"raw_provenance":if retain {"original_response"} else {"withheld_unsafe_or_unreviewed_response"}})
}

fn response_assessment(
    _status: u16,
    header_challenge: bool,
    bytes: &[u8],
    content_type: Option<&str>,
    complete: bool,
) -> ChallengeAssessment {
    if header_challenge {
        ChallengeAssessment::Detected
    } else {
        assess_challenge_body(bytes, content_type, complete)
    }
}
fn response_content_type(headers: &reqwest::header::HeaderMap) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(reqwest::header::CONTENT_TYPE).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()
}

fn review_rejection(
    operation: &str,
    bytes: &[u8],
    content_type: Option<&str>,
    assessment: &ChallengeAssessment,
) -> Option<Value> {
    let reason = match assessment {
        ChallengeAssessment::Clear => return None,
        ChallengeAssessment::Detected => {
            "confirmed authentication challenge requires human review; no automatic retry attempted"
        }
        ChallengeAssessment::Unreviewed => {
            "response body could not be safely reviewed; admission refused and no automatic retry attempted"
        }
    };
    Some(
        json!({"operation":operation,"status":"blocked","reason":reason,
        "human_action_required":true,
        "evidence":evidence(bytes,content_type,"response withheld from raw fallback",assessment)}),
    )
}
fn observed_response_rejection(
    operation: &str,
    status: u16,
    retry: bool,
    challenge: bool,
    complete: bool,
) -> Option<Value> {
    if matches!(status, 401 | 403) {
        Some(
            json!({"operation":operation,"status":"blocked","http_status":status,"reason":"HTTP authentication refused; shared safety latched; no automatic retry attempted","body_complete":complete}),
        )
    } else if challenge {
        Some(
            json!({"operation":operation,"status":"blocked","http_status":status,"reason":"confirmed challenge requires human review; shared safety latched; no automatic retry attempted","body_complete":complete}),
        )
    } else if status == 429 || retry {
        Some(
            json!({"operation":operation,"status":"blocked","http_status":status,"reason":"HTTP cooldown requires operator review; no automatic retry attempted","retry_after_present":retry,"body_complete":complete,"https_cas_acceptance":"unknown","service_contract_reason":if operation=="service" {Some(AUTH_REASON)} else {None}}),
        )
    } else {
        None
    }
}

/// Complete admitted/refused observation for one live response, computed
/// before the original shared lease settles. Newly issued cookies join an
/// invocation-only echo guard; they are never adopted, persisted or returned.
/// Denial, challenge, cooldown and body-failure facts remain independent.
/// `credential` is present only for the deliberately authenticated session
/// read: it screens the caller's SSO secrets and every value the in-memory
/// session jar holds (delivered, retired and transmitted spellings) against
/// the raw body, MIME metadata and the decoded result projection. Anonymous
/// requests pass `None`, leaving their behavior exactly as before.
struct LiveResponse<'a> {
    status: u16,
    retry: bool,
    challenge: bool,
    complete: bool,
    issued: &'a crate::net::IssuedCookies,
    credential: Option<&'a dyn Fn(&[u8]) -> bool>,
    assessment: &'a ChallengeAssessment,
    bytes: &'a [u8],
    content_type: Option<&'a str>,
}

/// Apply the session credential predicate to every string, key and scalar the
/// decoded response value produces, including number serializations and the
/// whitespace-collapsed spellings a projection can assemble across nodes.
fn credential_text_echoed(contains: &dyn Fn(&[u8]) -> bool, text: &str) -> bool {
    if contains(text.as_bytes()) {
        return true;
    }
    if !text.chars().any(char::is_whitespace) {
        return false;
    }
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    contains(compact.as_bytes())
}

fn credential_echoed_value(candidate: &Value, contains: &dyn Fn(&[u8]) -> bool) -> bool {
    match candidate {
        Value::String(text) => credential_text_echoed(contains, text),
        Value::Number(number) => credential_text_echoed(contains, &number.to_string()),
        Value::Array(items) => items
            .iter()
            .any(|item| credential_echoed_value(item, contains)),
        Value::Object(members) => members.iter().any(|(key, item)| {
            credential_text_echoed(contains, key) || credential_echoed_value(item, contains)
        }),
        _ => false,
    }
}

/// Stream every decoded JSON key/value against the session credential
/// predicate without collapsing duplicate members. This mirrors the
/// issued-cookie guard's decoded walk: a credential spelling that only
/// exists after JSON escape decoding is screened, and a JSON-shaped body
/// that cannot be completely decoded is refused rather than exported under
/// an unproven screen.
struct CredentialEchoSeed<'a> {
    contains: &'a dyn Fn(&[u8]) -> bool,
    echoed: &'a std::cell::Cell<bool>,
}

struct CredentialEchoKeySeed<'a> {
    contains: &'a dyn Fn(&[u8]) -> bool,
    echoed: &'a std::cell::Cell<bool>,
}

struct CredentialEchoVisitor<'a> {
    contains: &'a dyn Fn(&[u8]) -> bool,
    echoed: &'a std::cell::Cell<bool>,
}

impl<'de> serde::de::Visitor<'de> for CredentialEchoVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if !self.echoed.get() && credential_text_echoed(self.contains, value) {
            self.echoed.set(true);
        }
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        while seq
            .next_element_seed(CredentialEchoSeed {
                contains: self.contains,
                echoed: self.echoed,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        while map
            .next_key_seed(CredentialEchoKeySeed {
                contains: self.contains,
                echoed: self.echoed,
            })?
            .is_some()
        {
            map.next_value_seed(CredentialEchoSeed {
                contains: self.contains,
                echoed: self.echoed,
            })?;
        }
        Ok(())
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for CredentialEchoSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(CredentialEchoVisitor {
            contains: self.contains,
            echoed: self.echoed,
        })
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for CredentialEchoKeySeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(CredentialEchoVisitor {
            contains: self.contains,
            echoed: self.echoed,
        })
    }
}

/// Whether untrusted response bytes carry a credential in literal,
/// JSON-escaped or structured-decoded form. `contains` itself already covers
/// the reversible literal encodings (escaped text, base64, percent/form);
/// this wrapper adds the decoded-member walk for JSON-shaped bodies and
/// fails closed when that walk cannot complete.
fn credential_echoed(bytes: &[u8], contains: &dyn Fn(&[u8]) -> bool) -> bool {
    use serde::de::Deserializer as _;
    if contains(bytes) {
        return true;
    }
    if let Ok(text) = std::str::from_utf8(bytes)
        && text.chars().any(char::is_whitespace)
        && credential_text_echoed(contains, text)
    {
        return true;
    }
    // JSON may escape a literal solidus as `\/` even when the surrounding
    // bytes are malformed or have a non-JSON prefix. Review that equivalent
    // spelling without depending on a successful document parse, mirroring
    // the issued-cookie guard's decoded pass.
    if bytes.windows(2).any(|pair| pair == b"\\/") {
        let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index..].starts_with(b"\\/") {
                decoded.push(b'/');
                index += 2;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        if contains(&decoded) {
            return true;
        }
    }
    let echoed = std::cell::Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = deserializer.deserialize_any(CredentialEchoVisitor {
        contains,
        echoed: &echoed,
    });
    let complete = parsed.is_ok() && deserializer.end().is_ok();
    let json_shaped = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| matches!(byte, b'{' | b'[' | b'"'));
    echoed.into_inner() || (!complete && json_shaped)
}

fn credential_html_echoed(
    bytes: &[u8],
    content_type: Option<&str>,
    contains: &dyn Fn(&[u8]) -> bool,
) -> bool {
    if !content_type.is_some_and(|value| {
        value.split(';').next().is_some_and(|mime| {
            mime.trim().eq_ignore_ascii_case("text/html")
                || mime.trim().eq_ignore_ascii_case("application/xhtml+xml")
        })
    }) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let document = Html::parse_document(text);
    let full_text = document
        .root_element()
        .descendants()
        .filter_map(|node| node.value().as_text())
        .fold(String::new(), |mut combined, text| {
            combined.push_str(text);
            combined
        });
    if credential_text_echoed(contains, &full_text) {
        return true;
    }
    let elements = Selector::parse("*").expect("constant selector");
    document.select(&elements).any(|element| {
        element.value().attrs().any(|(name, value)| {
            credential_text_echoed(contains, name)
                || credential_text_echoed(contains, value)
        })
    })
}

fn live_admission(operation: &str, response: LiveResponse<'_>) -> Value {
    let LiveResponse {
        status,
        retry,
        challenge,
        complete,
        issued,
        credential,
        assessment,
        bytes,
        content_type,
    } = response;
    if let Some(rejection) =
        observed_response_rejection(operation, status, retry, challenge, complete)
    {
        return rejection;
    }
    if !complete {
        return blocked(
            operation,
            "response incomplete or exceeds byte limit; no subsequent request permitted",
        );
    }
    if issued.overflowed()
        || issued.echoed(bytes)
        || content_type.is_some_and(|value| issued.echoed(value.as_bytes()))
    {
        return json!({"operation":operation,"status":"blocked","http_status":status,"body_complete":complete,
        "reason":"response echoed newly issued session material or its cookie headers could not be reviewed; body and metadata withheld"});
    }
    if credential.is_some_and(|contains| {
        credential_echoed(bytes, contains)
            || credential_html_echoed(bytes, content_type, contains)
            || content_type.is_some_and(|value| contains(value.as_bytes()))
    }) {
        return json!({"operation":operation,"status":"blocked","http_status":status,"body_complete":complete,
        "reason":"response echoed authentication session material; body and metadata withheld"});
    }
    if let Some(rejection) = review_rejection(operation, bytes, content_type, assessment) {
        return rejection;
    }
    let result = if operation == "service" {
        json!({"operation":operation,"status":"unsupported","reason":AUTH_REASON,"https_probe_status":status,"https_cas_acceptance":"unknown","evidence":evidence(bytes,content_type,"HTTPS callback reachability does not prove CAS service acceptance",assessment)})
    } else if status != 200 {
        json!({"operation":operation,"status":"blocked","reason":"HTTP response requires operator review; redirects are not followed","http_status":status,"evidence":evidence(bytes,content_type,"non-success response",assessment)})
    } else {
        parse_page_assessed(bytes, content_type, operation, assessment, credential)
    };
    if issued.echoed_value(&result) {
        return json!({"operation":operation,"status":"blocked","http_status":status,"body_complete":complete,
        "reason":"decoded response projection echoed newly issued session material; output withheld"});
    }
    if credential
        .is_some_and(|contains| credential_echoed_value(&result, contains))
    {
        return json!({"operation":operation,"status":"blocked","http_status":status,"body_complete":complete,
        "reason":"decoded response projection echoed authentication session material; output withheld"});
    }
    result
}
// Accept only one unambiguous, literal assignment. Never execute page scripts.
fn csrf(text: &str) -> Option<&str> {
    let mut found = None;
    for tail in text.split("var csrf_token").skip(1) {
        let tail = tail.trim_start().strip_prefix('=')?.trim_start();
        let quote = tail.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        let rest = &tail[1..];
        let end = rest.find(quote)?;
        let token = &rest[..end];
        if token.is_empty()
            || token.len() > 4096
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-./+=".contains(&b))
            || !rest[end + 1..].trim_start().starts_with(';')
            || found.is_some()
        {
            return None;
        }
        found = Some(token);
    }
    found
}

fn parse_page(bytes: &[u8], content_type: Option<&str>, operation: &str) -> Value {
    let assessment = assess_challenge_body(bytes, content_type, true);
    parse_page_assessed(bytes, content_type, operation, &assessment, None)
}

fn reports_missing_authentication(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).ok().map(str::trim)
        == Some("<script>alert('未获取到认证信息，请退出后重新进入');history.back()</script>")
}

fn parse_page_assessed(
    bytes: &[u8],
    content_type: Option<&str>,
    operation: &str,
    assessment: &ChallengeAssessment,
    credential: Option<&dyn Fn(&[u8]) -> bool>,
) -> Value {
    if let Some(rejection) = review_rejection(operation, bytes, content_type, assessment) {
        return rejection;
    }
    if reports_missing_authentication(bytes) {
        return json!({"operation":operation,"status":"blocked","authentication_required":true,
        "reason":"upstream explicitly reported missing authentication; a deliberate authenticated session is required",
        "read_only":true,"submitted":false,"written_requests":0,
        "evidence":evidence(bytes,content_type,"upstream missing-authentication response retained without following its script",assessment)});
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"response is not UTF-8",assessment)});
    };
    let Some(token) = csrf(text) else {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"missing or ambiguous literal csrf_token assignment",assessment)});
    };
    let document = Html::parse_document(text);
    let selector = Selector::parse("body").expect("constant selector");
    let visible: Vec<_> = document
        .select(&selector)
        .flat_map(|body| body.descendants())
        .filter_map(|node| {
            if node
                .ancestors()
                .filter_map(scraper::ElementRef::wrap)
                .any(|el| {
                    matches!(
                        el.value().name(),
                        "script" | "style" | "template" | "noscript"
                    )
                })
            {
                return None;
            }
            node.value().as_text().map(|s| {
                let text: &str = s;
                text
            })
        })
        .filter(|s| !s.is_empty())
        .collect();
    let original_visible = visible.concat();
    let compact_visible: String = original_visible
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if credential.is_some_and(|contains| {
        credential_text_echoed(contains, &original_visible)
            || credential_text_echoed(contains, &compact_visible)
    }) {
        return json!({"operation":operation,"status":"blocked","read_only":true,"submitted":false,
        "reason":"decoded visible response echoed authentication session material; output withheld"});
    }
    if crate::net::carries_secret(original_visible.as_bytes(), token)
        || crate::net::carries_secret(compact_visible.as_bytes(), token)
    {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"sensitive visible response withheld",assessment)});
    }
    let visible = visible
        .iter()
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if crate::net::carries_secret(visible.as_bytes(), token) || sensitive_text(visible.as_bytes()) {
        return json!({"operation":operation,"status":"degraded","evidence":evidence(bytes,content_type,"sensitive visible response withheld",assessment)});
    }
    json!({"operation":operation,"status":"ok","read_only":true,"submitted":false,
        "csrf_token_present":true,"visible_page_text":visible,
        "schedule_structure_verified":false,"shift_count":null,
        "availability":null,"remaining_seats":null,"availability_inferred":false,
        "availability_reason":AVAILABILITY_REASON,
        "evidence":evidence(bytes,content_type,"original page retained for offline re-reading when safe",assessment)})
}

/// Read-only schedule projection. The page's shift table is unverified, so no
/// shift is admitted and no seat availability is inferred; completeness states
/// that absence explicitly instead of returning a silently partial list.
fn schedule_observation(mut observation: Value, route: u64, date: &str) -> Value {
    let admitted = observation.get("status").and_then(Value::as_str) == Some("ok");
    observation["route"] = json!(route);
    observation["date"] = json!(date);
    observation["read_only"] = json!(true);
    observation["submitted"] = json!(false);
    observation["written_requests"] = json!(0);
    observation["schedule"] = if admitted { json!([]) } else { Value::Null };
    observation["schedule_count"] = json!(0);
    observation["schedule_complete"] = json!(false);
    observation["completeness"] = json!({
        "scope":"single_admitted_schedule_page",
        "status":if admitted {"unknown"} else {"not_observed"},
        "complete":false,
        "exhaustive":false,
        "list_structure_verified":false,
        "returned_shift_count":0,
        "source_reported_shift_count":null,
        "omitted_shift_count":null,
        "max_response_bytes":LIMIT,
        "truncated":if admitted {json!(false)} else {Value::Null},
        "pagination_followed":false,
        "external_links_followed":false,
        "availability_inferred":false,
        "reason":if admitted {SCHEDULE_REASON} else {"no admitted schedule page; completeness unknown"}
    });
    observation
}

fn decorate_schedule(
    operation: &str,
    observation: Value,
    route: Option<u64>,
    date: Option<&str>,
) -> Value {
    match (operation, route, date) {
        ("schedule", Some(route), Some(date)) => schedule_observation(observation, route, date),
        _ => observation,
    }
}

fn purchase_response(bytes: &[u8], content_type: Option<&str>) -> Value {
    let assessment = assess_challenge_body(bytes, content_type, true);
    if let Some(mut rejection) = review_rejection("purchase", bytes, content_type, &assessment) {
        rejection["refusal_code"] = json!(MUTATION_REFUSAL_CODE);
        rejection["missing_preconditions"] = json!(MUTATION_REQUIRED);
        return rejection;
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value)
            if !sensitive_value(&value)
                && value.is_object()
                && value.get("message").and_then(Value::as_str).is_some() =>
        {
            json!({"operation":"purchase","status":"observed","read_only":true,
                "submitted":false,"purchase_possible":false,"written_requests":0,
                "refusal_code":MUTATION_REFUSAL_CODE,"missing_preconditions":MUTATION_REQUIRED,
                "order_state":"unverified","postcondition_verified":false,
                "postcondition_reason":"caller-supplied response bytes are not an independent order postcondition; this module never submits an order",
                "upstream_message_claims_success":value["message"].as_str()==Some("下单成功"),
                "message":value["message"],
                "payment_link_present":value.get("url").and_then(Value::as_str).is_some_and(|s| !s.is_empty()),
                "paid":null,
                "evidence":evidence(bytes,content_type,"observed response only; not an independently verified order",&assessment)})
        }
        _ => json!({"operation":"purchase","status":"degraded",
            "refusal_code":MUTATION_REFUSAL_CODE,"missing_preconditions":MUTATION_REQUIRED,
            "evidence":evidence(bytes,content_type,"purchase response lacks a string message",&assessment)}),
    }
}

fn validate(value: &Value) -> Result<&str, Error> {
    let object = value.as_object().ok_or_else(invalid)?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let fields: &[&str] = match operation {
        "page" | "availability" => &["operation", "date", "shifts_number", "source"],
        "schedule" => &["operation", "date", "route", "source"],
        "purchase" => &[
            "operation",
            "date",
            "shifts_number",
            "captcha",
            "intent",
            "confirm",
            "response",
        ],
        "cancel" | "service" => &["operation"],
        _ => return Err(invalid()),
    };
    if object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(invalid());
    }
    if matches!(operation, "page" | "availability" | "purchase") {
        if !valid_date(value) || !valid_identifier(value, "shifts_number") {
            return Err(invalid());
        }
    } else if operation == "schedule" {
        if !valid_date(value) || !valid_identifier(value, "route") {
            return Err(invalid());
        }
    }
    for field in ["captcha", "intent", "confirm"] {
        if let Some(v) = value.get(field) {
            if !v.as_str().is_some_and(|s| {
                !s.is_empty() && s.chars().count() <= 4096 && !s.chars().any(char::is_control)
            }) {
                return Err(invalid());
            }
        }
    }
    for field in ["source", "response"] {
        if let Some(source) = value.get(field) {
            let source = source.as_object().ok_or_else(invalid)?;
            if source.len() != 2
                || !source.contains_key("body_base64")
                || !source.contains_key("content_type")
                || !(source["content_type"].is_null() || source["content_type"].is_string())
            {
                return Err(invalid());
            }
            let encoded = source["body_base64"].as_str().ok_or_else(invalid)?;
            if encoded.len() > LIMIT * 2
                || STANDARD.decode(encoded).map_err(|_| invalid())?.len() > LIMIT
            {
                return Err(invalid());
            }
        }
    }
    Ok(operation)
}

/// Input is stdin JSON. Supplied source/response bytes are offline observations,
/// never authorization, a session, or evidence that this module sent an order.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > LIMIT * 2 + 16384 {
        return Err(invalid());
    }
    // StrictValue rejects duplicate object members so a repeated route/date or
    // purchase field cannot be resolved by last-wins.
    let value: Value = serde_json::from_str::<StrictValue>(input)
        .map_err(|_| invalid())?
        .0;
    let operation = validate(&value)?;
    let route = if operation == "schedule" {
        Some(value["route"].as_u64().ok_or_else(invalid)?)
    } else {
        None
    };
    let date = if operation == "schedule" {
        Some(value["date"].as_str().ok_or_else(invalid)?)
    } else {
        None
    };
    if operation == "cancel" {
        return Ok(
            json!({"operation":operation,"status":"unsupported","submitted":false,"written_requests":0,
            "refusal_code":MUTATION_REFUSAL_CODE,"missing_preconditions":MUTATION_REQUIRED,
            "postcondition_verified":false,
            "reason":"Neither upstream branch implements cancellation; no cancellation endpoint is known."}),
        );
    }
    if operation == "purchase" {
        if let Some(source) = value.get("response") {
            let bytes = STANDARD
                .decode(source["body_base64"].as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            return Ok(purchase_response(&bytes, source["content_type"].as_str()));
        }
        let Some(captcha) = value.get("captcha").and_then(Value::as_str) else {
            return Ok(
                json!({"operation":operation,"status":"blocked","submitted":false,"written_requests":0,
                "refusal_code":MUTATION_REFUSAL_CODE,
                "missing_preconditions":missing_purchase_preconditions(&value,false),
                "postcondition_verified":false,
                "reason":"captcha must be provided by a human; no recognition or retrieval retries are performed",
                "human_action_required":true,"safety_latched":true,"latch_scope":"this purchase intent; no request can proceed without explicit human captcha input"}),
            );
        };
        let preview = json!({"intent":PURCHASE_INTENT,"date":value["date"],
            "shifts_number":value["shifts_number"],"captcha_sha256":digest(captcha.as_bytes()),
            "submission_count":0,"payment_automation":false});
        let hash = digest(&serde_json::to_vec(&preview).map_err(|_| invalid())?);
        let confirmed = value.get("intent").and_then(Value::as_str) == Some(PURCHASE_INTENT)
            && value.get("confirm").and_then(Value::as_str) == Some(hash.as_str());
        if !confirmed {
            return Ok(json!({"operation":operation,"status":"preview",
                "refusal_code":MUTATION_REFUSAL_CODE,
                "missing_preconditions":missing_purchase_preconditions(&value,false),
                "postcondition_verified":false,
                "preview":preview,"preview_sha256":hash,"preview_immutable":true,
                "confirmation_required":true,"submitted":false,"written_requests":0}));
        }
        return Ok(json!({"operation":operation,"status":"unsupported",
            "refusal_code":MUTATION_REFUSAL_CODE,
            "missing_preconditions":missing_purchase_preconditions(&value,true),
            "postcondition_verified":false,
            "reason":AUTH_REASON,
            "additional_blocker":"No independent order postcondition endpoint or authenticated session contract is documented. No submission is made, including repeated confirmations.",
            "preview":preview,"preview_sha256":hash,"preview_immutable":true,
            "submitted":false,"written_requests":0}));
    }
    if let Some(source) = value.get("source") {
        let bytes = STANDARD
            .decode(source["body_base64"].as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        return Ok(decorate_schedule(
            operation,
            parse_page(&bytes, source["content_type"].as_str(), operation),
            route,
            date,
        ));
    }
    if !online {
        return Ok(decorate_schedule(
            operation,
            blocked(
                operation,
                "offline mode requires retained source bytes; no request was made",
            ),
            route,
            date,
        ));
    }
    let path = if operation == "service" {
        "/wechat/CASLogin".to_owned()
    } else {
        let date = if operation == "schedule" {
            date.ok_or_else(invalid)?
        } else {
            value["date"].as_str().ok_or_else(invalid)?
        };
        let route = if operation == "schedule" {
            route.ok_or_else(invalid)?
        } else {
            value["shifts_number"].as_u64().ok_or_else(invalid)?
        };
        format!("/wechat/ticketInfoPage?shifts_date={date}&{ROUTE_PARAMETER}={route}")
    };
    let client = Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| Error::new("network_error", "cannot construct shuttle HTTPS client"))?;
    let governor = match Governor::open() {
        Ok(g) => g,
        Err(_) => {
            return Ok(decorate_schedule(
                operation,
                blocked(operation, "shared governor unavailable"),
                route,
                date,
            ));
        }
    };
    let mut lease = match governor.try_acquire(RequestKind::Interactive) {
        Ok(l) => l,
        Err(_) => {
            return Ok(decorate_schedule(
                operation,
                blocked(
                    operation,
                    "shared governor refused this request; no retry attempted",
                ),
                route,
                date,
            ));
        }
    };
    let request = client
        .get(format!("{ORIGIN}{path}"))
        .timeout(Duration::from_secs(30));
    let response = match lease.start_request(|| request.send()) {
        Ok(result) => result,
        Err(FollowupError::Governor(_)) => {
            return Err(Error::new(
                "governor_error",
                "cannot admit shuttle request; pending outcome retained",
            ));
        }
    };
    let mut response = match response {
        Ok(r) => r,
        Err(_) => {
            lease.finish(Outcome::NetworkFailure).map_err(|_| {
                Error::new("governor_error", "cannot persist shuttle request outcome")
            })?;
            return Ok(decorate_schedule(
                operation,
                blocked(operation, "HTTPS request failed; no retry attempted"),
                route,
                date,
            ));
        }
    };
    let status = response.status().as_u16();
    let header_challenge = response
        .headers()
        .iter()
        .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
    let content_type = response_content_type(response.headers());
    let mime_reviewed = content_type.is_ok();
    let content_type = content_type.unwrap_or(None).map(str::to_owned);
    let retry = response
        .headers()
        .contains_key(reqwest::header::RETRY_AFTER);
    let retry_after = response
        .headers()
        .get_all("retry-after")
        .iter()
        .find_map(|value| value.to_str().ok())
        .map(str::to_owned);
    if lease
        .observe_http_many(
            status,
            response
                .headers()
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            header_challenge,
        )
        .is_err()
    {
        drop(response);
        return Err(Error::new(
            "governor_error",
            "cannot persist shuttle HTTP headers",
        ));
    }
    // Issuance alone is not a challenge or an authentication rejection. Keep
    // every newly issued spelling only for this invocation's echo screen.
    let mut issued = crate::net::IssuedCookies::new();
    for value in response.headers().get_all(reqwest::header::SET_COOKIE) {
        issued.absorb(value.to_str().ok());
    }
    let mut bytes = Vec::new();
    let read = response
        .by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes);
    let complete = read.is_ok() && bytes.len() <= LIMIT;
    let mut assessment = response_assessment(
        status,
        header_challenge,
        &bytes,
        content_type.as_deref(),
        complete,
    );
    if !mime_reviewed && matches!(&assessment, ChallengeAssessment::Clear) {
        assessment = ChallengeAssessment::Unreviewed;
    }
    // Cancel any unread body while the original shared lease is still held.
    drop(response);
    let challenge = matches!(&assessment, ChallengeAssessment::Detected);
    let result = live_admission(
        operation,
        LiveResponse {
            status,
            retry,
            challenge,
            complete,
            issued: &issued,
            credential: None,
            assessment: &assessment,
            bytes: &bytes,
            content_type: content_type.as_deref(),
        },
    );
    if result["authentication_required"] == true {
        lease.finish(Outcome::CredentialRejected)
    } else {
        lease.finish(Outcome::Http {
            status,
            retry_after: retry_after.as_deref(),
            challenge,
            network_failure: !complete,
        })
    }
    .map_err(|_| Error::new("governor_error", "cannot persist shuttle request outcome"))?;
    Ok(decorate_schedule(operation, result, route, date))
}

/// Bounded stdin for `buaa shuttle session`: credentials plus one small read
/// descriptor, never a document. The session boundary itself limits it.
const SESSION_INPUT_LIMIT: usize = 65536;

fn session_error(code: &'static str, message: &'static str) -> Error {
    Error::new(code, message)
}

fn session_invalid() -> Error {
    session_error(
        "invalid_input",
        "shuttle session input does not match the session contract",
    )
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

// Serde's struct derives also accept positional sequences. This boundary
// admits JSON objects only, without a credential-bearing Value tree.
fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
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
    date: String,
    route: u64,
}

impl<'de> Deserialize<'de> for SessionRead {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            enabled: bool,
            date: String,
            shifts_number: u64,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            enabled: raw.enabled,
            date: raw.date,
            route: raw.shifts_number,
        })
    }
}

/// Add the read descriptor and the fixed read-only/provenance facts to any
/// session outcome without touching the admitted observation fields. An
/// enabled read always states that availability is not inferred.
fn session_observation(mut observation: Value, date: &str, route: u64) -> Value {
    observation["operation"] = json!("session");
    observation["date"] = json!(date);
    observation["shifts_number"] = json!(route);
    observation["read_only"] = json!(true);
    observation["submitted"] = json!(false);
    observation["written_requests"] = json!(0);
    observation["availability_inferred"] = json!(false);
    observation["availability_reason"] = json!(AVAILABILITY_REASON);
    observation["service"] = json!("zhihuixiaoche");
    observation["source"] = json!("network");
    observation["network_performed"] = json!(true);
    observation["write_operations_performed"] = json!(false);
    observation["session_persistent"] = json!(false);
    observation["session_refresh"] = json!(false);
    observation["automatic_retry"] = json!(false);
    observation
}

/// Book the follow-up read slot under the shared governor. A cooldown is a
/// durable refusal; pacing sleeps before transmission, never during the CAS
/// redirect chain (handled inside the authentication itself).
fn admit_session_read(lease: &mut RequestLease<'_>) -> Result<(), Error> {
    let reservation = lease.reserve_followup().map_err(|_| {
        session_error("governor_error", "cannot admit shuttle session follow-up")
    })?;
    if !reservation.cooldown_wait.is_zero() {
        return Err(session_error(
            "cooldown",
            "shuttle authentication was deferred; no read or retry was sent",
        ));
    }
    if !reservation.request_wait.is_zero() {
        std::thread::sleep(reservation.request_wait);
    }
    Ok(())
}

/// One explicit in-memory CAS login to the shuttle service followed by exactly
/// one read-only ticketInfoPage GET. The session never persists, refreshes or
/// retries; the issued cookie is used for the single read only, and the read
/// body is screened against every credential value the attempt held.
pub fn session(input: &str, online: bool) -> Result<Value, Error> {
    session_with_network(input, online, || {
        Ok((
            cas::http_client()?,
            Governor::open().map_err(|_| {
                session_error("governor_error", "shared request admission unavailable")
            })?,
        ))
    })
}

pub(crate) fn session_with_network(
    input_text: &str,
    online: bool,
    network: impl FnOnce() -> Result<(Client, Governor), Error>,
) -> Result<Value, Error> {
    if input_text.len() > SESSION_INPUT_LIMIT {
        return Err(session_invalid());
    }
    let mut deserializer = serde_json::Deserializer::from_str(input_text);
    let input: SessionInput =
        deserialize_object(&mut deserializer).map_err(|_| session_invalid())?;
    deserializer.end().map_err(|_| session_invalid())?;
    if !input.read.enabled {
        return Ok(json!({"result":"disabled","read_only":true,"submitted":false,
            "written_requests":0,"service":"zhihuixiaoche","network_performed":false,
            "write_operations_performed":false}));
    }
    // Reuse the shared read descriptor validators: the session read is the
    // same ticketInfoPage contract as the anonymous page/availability reads.
    let descriptor = json!({"date": &input.read.date, "shifts_number": input.read.route});
    if !valid_date(&descriptor) || !valid_identifier(&descriptor, "shifts_number") {
        return Err(session_invalid());
    }
    if !input.authorized {
        return Err(session_error(
            "permission",
            "explicit authorization for one shuttle authentication attempt is required",
        ));
    }
    let credentials = SsoCredentials::new(&input.username, &input.password)?;
    if input
        .intent
        .strip_prefix("LOGIN ")
        .and_then(|value| value.strip_suffix(" shuttle"))
        != Some(input.username.as_str())
    {
        return Err(session_invalid());
    }
    if !online {
        return Err(session_error(
            "online_required",
            "shuttle sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let (client, governor) = network()?;
    let mut lease = crate::net::acquire_kind(&governor, RequestKind::Authentication)?;
    // One authentication RequestLease spans the whole CAS exchange and the
    // single fixed read: no separate governor acquisition follows the login.
    let prepared = cas::authenticate_service(&mut lease, &client, CasService::Shuttle, credentials)
        .and_then(|mut session| {
            let url = url::Url::parse(&format!(
                "{ORIGIN}/wechat/ticketInfoPage?shifts_date={}&{ROUTE_PARAMETER}={}",
                input.read.date, input.read.route
            ))
            .map_err(|_| session_invalid())?;
            let (cookie, expiry) = session.cookie_header_for_transmission(&url)?;
            let cookie = cookie.ok_or_else(|| {
                session_error(
                    "auth_latched",
                    "the shuttle session has no usable scoped cookie; no read was sent",
                )
            })?;
            admit_session_read(&mut lease)?;
            let mut request = client
                .get(url.clone())
                .header(reqwest::header::COOKIE, cookie)
                .header("Accept", "text/html")
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|_| session_invalid())?;
            if let Some(value) = request.headers_mut().get_mut("cookie") {
                value.set_sensitive(true);
            }
            Ok((session, expiry, url, request))
        });
    let (mut session, cookie_expiry, url, request) = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            if matches!(
                failure.code,
                "governor_error" | "governor_denied" | "governor_unavailable"
            ) {
                // Persistence failure after a send is not a local refusal.
                // Drop without finishing: retain the pending outcome for review.
                return Err(failure);
            }
            let settled = match failure.code {
                "auth_latched" => lease.finish(Outcome::CredentialRejected),
                "challenge_requires_human" => lease.finish(Outcome::CaptchaRequired),
                "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
                _ => lease.finish_without_request(),
            };
            settled.map_err(|_| {
                session_error("governor_error", "cannot settle shuttle authentication attempt")
            })?;
            return Err(failure);
        }
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
                .map_err(|_| session_error("governor_error", "cannot settle shuttle request"))?;
            return Err(session_error(
                "network_error",
                "shuttle session read failed; no automatic retry",
            ));
        }
        Ok(None) => {
            lease
                .finish_without_request()
                .map_err(|_| session_error("governor_error", "cannot release shuttle request"))?;
            return Err(session_error(
                "scoped_cookie_unusable",
                "the shuttle cookie expired before transmission; no request was sent",
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
    let header_challenge = response
        .headers()
        .iter()
        .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
    let content_type = response_content_type(response.headers());
    let mime_reviewed = content_type.is_ok();
    let content_type = content_type.unwrap_or(None).map(str::to_owned);
    let retry = response
        .headers()
        .contains_key(reqwest::header::RETRY_AFTER);
    let retry_after = response
        .headers()
        .get_all("retry-after")
        .iter()
        .find_map(|value| value.to_str().ok())
        .map(str::to_owned);
    if lease
        .observe_http_many(
            status,
            response
                .headers()
                .get_all("retry-after")
                .iter()
                .map(|value| value.to_str().ok()),
            header_challenge,
        )
        .is_err()
    {
        drop(response);
        return Err(session_error(
            "governor_error",
            "cannot persist shuttle response headers",
        ));
    }
    // Absorb the read response's Set-Cookie declarations into the session jar
    // before screening: every newly issued value joins the invocation-only
    // credential guard, and a declaration the jar cannot review refuses the
    // whole read rather than leaving material unscreened. Nothing is
    // persisted, retransmitted or replayed.
    if let Err(failure) = session.absorb_shuttle_headers(&url, response.headers()) {
        drop(response);
        let settled = match failure.code {
            "governor_error" | "governor_denied" | "governor_unavailable" => return Err(failure),
            "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
            _ => lease.finish_without_request(),
        };
        settled.map_err(|_| {
            session_error("governor_error", "cannot settle shuttle session read")
        })?;
        return Err(failure);
    }
    // Keep the raw declaration spellings in the module's own echo guard too so
    // the existing issued-cookie refusal stays exact for the anonymous path's
    // contract while the session jar adds the authenticated screen.
    let mut issued = crate::net::IssuedCookies::new();
    for value in response.headers().get_all(reqwest::header::SET_COOKIE) {
        issued.absorb(value.to_str().ok());
    }
    let mut bytes = Vec::new();
    let read = response
        .by_ref()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes);
    let complete = read.is_ok() && bytes.len() <= LIMIT;
    let mut assessment = response_assessment(
        status,
        header_challenge,
        &bytes,
        content_type.as_deref(),
        complete,
    );
    if !mime_reviewed && matches!(&assessment, ChallengeAssessment::Clear) {
        assessment = ChallengeAssessment::Unreviewed;
    }
    // Cancel any unread body while the original shared lease is still held.
    drop(response);
    let challenge = matches!(&assessment, ChallengeAssessment::Detected);
    // The one read guards on the transmitted cookie header, the whole session
    // jar and the caller's SSO secrets: a response that echoes any of them is
    // withheld, never base64-exported. The jar now also holds this response's
    // issued values, so the screen covers every credential the attempt met.
    let contains = |candidate: &[u8]| {
        crate::net::carries_secret(candidate, &input.username)
            || crate::net::carries_secret(candidate, &input.password)
            || session.contains_secret_bytes(candidate)
    };
    let result = live_admission(
        "session",
        LiveResponse {
            status,
            retry,
            challenge,
            complete,
            issued: &issued,
            credential: Some(&contains),
            assessment: &assessment,
            bytes: &bytes,
            content_type: content_type.as_deref(),
        },
    );
    if result["authentication_required"] == true {
        lease.finish(Outcome::CredentialRejected)
    } else {
        lease.finish(Outcome::Http {
            status,
            retry_after: retry_after.as_deref(),
            challenge,
            network_failure: !complete,
        })
    }
    .map_err(|_| session_error("governor_error", "cannot persist shuttle request outcome"))?;
    Ok(session_observation(result, &input.read.date, input.read.route))
}

/// Exact input field/null contract; output is a tagged observation envelope.
pub fn schema() -> Value {
    let source = json!({"type":"object","additionalProperties":false,"required":["body_base64","content_type"],"properties":{"body_base64":{"type":"string","contentEncoding":"base64","description":"Decoded maximum 4194304 bytes"},"content_type":{"type":["string","null"]}}});
    let mut branches = Vec::new();
    for operation in [
        "page",
        "availability",
        "schedule",
        "purchase",
        "cancel",
        "service",
    ] {
        let mut properties = serde_json::Map::new();
        properties.insert("operation".into(), json!({"const":operation}));
        let mut required = vec!["operation"];
        if matches!(operation, "page" | "availability" | "purchase") {
            required.extend(["date", "shifts_number"]);
            properties.insert(
                "date".into(),
                json!({"type":"string","format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}),
            );
            properties.insert(
                "shifts_number".into(),
                json!({"type":"integer","minimum":1,"maximum":u32::MAX}),
            );
        } else if operation == "schedule" {
            required.extend(["date", "route"]);
            properties.insert(
                "date".into(),
                json!({"type":"string","format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"}),
            );
            properties.insert("route".into(),json!({"type":"integer","minimum":1,"maximum":u32::MAX,"description":"Exact upstream numeric route identifier (shifts_number); route names are never translated."}));
        }
        if operation == "purchase" {
            for field in ["captcha", "intent", "confirm"] {
                properties.insert(field.into(),json!({"type":"string","minLength":1,"maxLength":4096,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$"}));
            }
            properties.insert("response".into(), source.clone());
        } else if matches!(operation, "page" | "availability" | "schedule") {
            properties.insert("source".into(), source.clone());
        }
        branches.push(json!({"type":"object","additionalProperties":false,"required":required,"properties":properties}));
    }
    json!({
        "input":{"oneOf":branches},
        "output":{"type":"object","required":["operation","status"],"properties":{
            "operation":{"enum":["page","availability","schedule","purchase","cancel","service","session"]},
            "status":{"enum":["ok","blocked","unsupported","preview","observed","degraded"]},
            "authentication_required":{"const":true,"description":"The upstream explicitly reported missing authentication; no page script was executed and no authenticated retry occurred."},
            "refusal_code":{"type":"string","const":MUTATION_REFUSAL_CODE,
                "description":"Set when purchase or cancel cannot proceed: exact typed intent, immutable preview confirmation and an independent postcondition are all required."},
            "missing_preconditions":{"type":"array","items":{"enum":["exact_typed_intent","immutable_preview_confirmation","independent_postcondition"]}},
            "read_only":{"type":"boolean"},
            "submitted":{"type":"boolean"},
            "written_requests":{"type":"integer","minimum":0},
            "preview_immutable":{"type":"boolean"},
            "postcondition_verified":{"type":"boolean"},
            "route":{"type":"integer","minimum":1,"maximum":u32::MAX},
            "date":{"type":"string"},
            "schedule":{"type":["array","null"],
                "description":"Admitted shift records; empty while the upstream shift-table structure is unverified, null when no schedule page was admitted."},
            "schedule_count":{"type":"integer","minimum":0},
            "schedule_complete":{"const":false},
            "completeness":{"type":"object","required":["complete","reason"],"properties":{
                "scope":{"type":"string"},
                "status":{"enum":["unknown","not_observed"]},
                "complete":{"const":false},
                "exhaustive":{"const":false},
                "list_structure_verified":{"const":false},
                "returned_shift_count":{"type":"integer","minimum":0},
                "source_reported_shift_count":{"type":["integer","null"]},
                "omitted_shift_count":{"type":["integer","null"]},
                "max_response_bytes":{"type":"integer","minimum":1},
                "truncated":{"type":["boolean","null"]},
                "pagination_followed":{"const":false},
                "external_links_followed":{"const":false},
                "availability_inferred":{"const":false},
                "reason":{"type":"string"}}}
        },"additionalProperties":true},
        "mutation_policy":{"operations":["purchase","cancel"],"refusal_code":MUTATION_REFUSAL_CODE,
            "required":["exact_typed_intent","immutable_preview_confirmation","independent_postcondition"],
            "reason":"No purchase or cancel is executed without all three; seat availability is never inferred."},
        "session":{
            "description":"One explicit in-memory CAS login to zhihuixiaoche.buaa.edu.cn followed by exactly one read-only GET of /wechat/ticketInfoPage under a single RequestLease. The reviewed plaintext CAS callback declaration is upgraded to HTTPS before any request; no plaintext is sent. Session cookies never persist, refresh or replay; every credential value the attempt held (SSO secrets, delivered/retired/transmitted cookie spellings) is screened from the read body, MIME metadata and decoded projection, and nothing credential-bearing is exported.",
            "input":{"type":"object","additionalProperties":false,
                "required":["authorized","username","password","intent","read"],
                "properties":{
                    "authorized":{"type":"boolean"},
                    "username":{"type":"string"},
                    "password":{"type":"string"},
                    "intent":{"type":"string"},
                    "read":{"type":"object","additionalProperties":false,
                        "required":["enabled","date","shifts_number"],
                        "properties":{
                            "enabled":{"type":"boolean"},
                            "date":{"type":"string","format":"date","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
                            "shifts_number":{"type":"integer","minimum":1,"maximum":u32::MAX}}}}},
            "intent":"LOGIN <username> shuttle",
            "output":{"description":"Same observation envelope as the anonymous read with operation \"session\", the echoed date/shifts_number descriptor and read-only provenance; a disabled read returns {\"result\":\"disabled\"} without opening transport or admission."},
            "lease":{"description":"The CAS exchange and the one ticketInfoPage GET share one authentication RequestLease; the read is booked as a follow-up reservation with normal pacing, and observed HTTP, challenge and body facts settle under that lease."},
            "privacy":{"description":"Credentials arrive through protected stdin into zeroizing fields only; no credential enters a JSON Value, the output or any cookie echo. Newly issued Set-Cookie values are absorbed into the invocation-only session jar before response screening."},
            "limits":{"input_utf8_bytes":SESSION_INPUT_LIMIT},
            "no_retry":{"description":"No automatic retry, redirect outside the generic CAS chain, session refresh or persistence; 401/403, challenges, cooldowns and incomplete bodies all refuse rather than resubmit."},
            "validation":"object root only; disabled read performs no I/O; enabled read requires valid date/shifts_number, authorized=true, exact intent and --online before opening transport or admission"},
        "limits":{"input_utf8_bytes":LIMIT*2+16384,"decoded_body_bytes":LIMIT},
        "online_verified":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_map_preserves_retry_values_and_refuses_ambiguous_mime() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER};
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(
            response_content_type(&headers),
            Ok(Some("application/json"))
        );
        headers.append(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        assert!(response_content_type(&headers).is_err());
        headers.remove(CONTENT_TYPE);
        headers.append(CONTENT_TYPE, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(response_content_type(&headers).is_err());
        headers.append(RETRY_AFTER, HeaderValue::from_static("0"));
        headers.append(RETRY_AFTER, HeaderValue::from_static("1800"));
        headers.append(RETRY_AFTER, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            headers
                .get_all("retry-after")
                .iter()
                .map(|v| v.to_str().ok())
                .collect::<Vec<_>>(),
            vec![Some("0"), Some("1800"), None]
        );
        headers.append("x-challenge", HeaderValue::from_static("none"));
        headers.append("x-challenge", HeaderValue::from_static("required"));
        assert!(
            headers
                .iter()
                .any(|(k, v)| crate::net::challenge_header(k.as_str(), v.as_bytes()))
        );
    }

    fn assert_challenge_latches(header_challenge: bool, body: &[u8]) {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "buaa-shuttle-challenge-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let governor = Governor::isolated_for_test(&path.join("governor")).unwrap();
        let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
        let assessment = response_assessment(200, header_challenge, body, Some("text/html"), true);
        let challenge = matches!(assessment, ChallengeAssessment::Detected);
        assert!(challenge);
        lease
            .finish(Outcome::Http {
                status: 200,
                retry_after: None,
                challenge,
                network_failure: false,
            })
            .unwrap();
        assert!(!governor.status().unwrap().safety_latched);
        assert!(governor.try_acquire(RequestKind::Interactive).is_err());
        drop(governor);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn http_200_header_only_challenge_latches_with_binary_body() {
        for (name, value) in [
            ("cf-mitigated", b"challenge".as_slice()),
            ("x-captcha", b"required".as_slice()),
            ("x-challenge", b"required".as_slice()),
            ("cf-chl-test", b"present".as_slice()),
        ] {
            assert_challenge_latches(crate::net::challenge_header(name, value), &[0xff, 0]);
        }
        assert!(matches!(
            response_assessment(
                200,
                crate::net::challenge_header("cf-mitigated", b"none"),
                b"ordinary page",
                Some("text/html"),
                true
            ),
            ChallengeAssessment::Clear
        ));
    }
    #[test]
    fn http_200_body_only_challenge_latches_without_headers() {
        assert_challenge_latches(false, b"<input name='captcha'>");
        assert!(matches!(
            response_assessment(
                200,
                false,
                b"<body>ordinary page</body>",
                Some("text/html"),
                true
            ),
            ChallengeAssessment::Clear
        ));
    }
    #[test]
    fn json_captcha_prose_is_not_a_challenge() {
        let body = br#"{"message":"CAPTCHA and getCaptchaImage are documentation terms"}"#;
        assert!(matches!(
            response_assessment(200, false, body, Some("application/json"), true),
            ChallengeAssessment::Clear
        ));
    }
    #[test]
    fn authentication_status_refuses_without_claiming_body_challenge() {
        use std::os::unix::fs::DirBuilderExt;
        for (status, complete, _expected_latch) in [
            (401, true, true),
            (403, true, true),
            (200, false, false),
            (200, true, false),
        ] {
            let path = std::env::temp_dir().join(format!(
                "buaa-shuttle-status-{}-{}-{}",
                std::process::id(),
                status,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            let governor = Governor::isolated_for_test(&path.join("governor")).unwrap();
            let lease = governor.try_acquire(RequestKind::Interactive).unwrap();
            let assessment = response_assessment(
                status,
                false,
                b"ordinary prose",
                Some("text/plain"),
                complete,
            );
            assert!(!matches!(&assessment, ChallengeAssessment::Detected));
            if !complete {
                assert!(matches!(&assessment, ChallengeAssessment::Unreviewed));
            }
            lease
                .finish(Outcome::Http {
                    status,
                    retry_after: None,
                    challenge: false,
                    network_failure: !complete,
                })
                .unwrap();
            assert_eq!(governor.status().unwrap().safety_latched, false);
            drop(governor);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn decoded_credentials_and_mime_parameters_are_withheld() {
        let body = br#"{"\u0074oken":"private_value"}"#;
        let result = purchase_response(body, Some("application/json; sessionid=private_value"));
        assert!(result["evidence"]["body_base64"].is_null());
        assert_eq!(result["evidence"]["content_type"], "application/json");
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn incomplete_body_is_unreviewed_but_header_remains_detected() {
        assert!(matches!(
            response_assessment(200, false, b"<html><body>", Some("text/html"), false),
            ChallengeAssessment::Unreviewed
        ));
        assert!(matches!(
            response_assessment(200, true, b"<html><body>", Some("text/html"), false),
            ChallengeAssessment::Detected
        ));
    }
    #[test]
    fn unreviewed_and_challenge_rejections_withhold_raw_content() {
        let unreviewed = review_rejection(
            "page",
            b"private body",
            Some("text/html"),
            &ChallengeAssessment::Unreviewed,
        )
        .unwrap();
        assert_eq!(unreviewed["status"], "blocked");
        assert!(unreviewed["evidence"]["body_base64"].is_null());
        assert!(
            !unreviewed["reason"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("captcha")
        );
        let detected = parse_page(b"<input name='captcha'>", Some("text/html"), "page");
        assert_eq!(detected["status"], "blocked");
        assert!(detected["evidence"]["body_base64"].is_null());
        assert!(!detected.to_string().contains("<input"));
    }
    #[test]
    fn token_echo_is_withheld_from_raw_fallback() {
        let result = parse_page(
            b"<script>var csrf_token='private_value';</script>",
            Some("text/html"),
            "page",
        );
        assert!(result["evidence"]["body_base64"].is_null());
        assert_eq!(result["evidence"]["raw_withheld"], true);
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn extracted_csrf_value_cannot_escape_through_visible_text() {
        let result = parse_page(
            b"<body>abc_123<script>var csrf_token='abc_123';</script></body>",
            Some("text/html"),
            "page",
        );
        assert_eq!(result["status"], "degraded");
        assert!(result["visible_page_text"].is_null());
        assert!(!result.to_string().contains("abc_123"));
    }
    #[test]
    fn split_csrf_values_are_not_returned_to_source_consumers() {
        for text in [
            "<span>abc</span><span>123</span>",
            "<span>ab c</span><span>1 23</span>",
        ] {
            let body = format!("<body>{text}<script>var csrf_token='abc123';</script></body>");
            let input = json!({"operation":"page","date":"2026-10-27","shifts_number":1,"source":{"body_base64":STANDARD.encode(body),"content_type":"text/html"}});
            let result = run(&input.to_string(), false).unwrap();
            assert_eq!(result["status"], "degraded");
            assert!(result["visible_page_text"].is_null());
            assert!(result["evidence"]["body_base64"].is_null());
        }
    }
    #[test]
    fn encoded_csrf_value_is_not_returned_to_source_consumers() {
        let body = b"<body>YWJjMTIz<script>var csrf_token='abc123';</script></body>";
        let input = json!({"operation":"page","date":"2026-10-27","shifts_number":1,"source":{"body_base64":STANDARD.encode(body),"content_type":"text/html"}});
        let result = run(&input.to_string(), false).unwrap();
        assert_eq!(result["status"], "degraded");
        assert!(result["visible_page_text"].is_null());
        assert!(!result.to_string().contains("YWJjMTIz"));
    }
    #[test]
    fn observed_refusal_survives_incomplete_body_and_service_cooldown() {
        for status in [401, 403] {
            let result =
                observed_response_rejection("service", status, false, false, false).unwrap();
            assert_eq!(result["http_status"], status);
            assert_eq!(result["body_complete"], false);
            assert!(!result["reason"].as_str().unwrap().contains("challenge"));
        }
        let result = observed_response_rejection("page", 200, false, true, false).unwrap();
        assert_eq!(result["body_complete"], false);
        assert!(result["reason"].as_str().unwrap().contains("challenge"));
        for (status, retry) in [(429, false), (200, true)] {
            let result =
                observed_response_rejection("service", status, retry, false, true).unwrap();
            assert_eq!(result["http_status"], status);
            assert_eq!(result["retry_after_present"], retry);
            assert_eq!(result["service_contract_reason"], AUTH_REASON);
        }
    }
    #[test]
    fn bearer_and_escaped_credential_responses_are_withheld() {
        for key in ["bearer", "jwt", "nonce", "loginname", "login_name"] {
            let result = purchase_response(
                json!({"message":"failed",(key):"synthetic_private"})
                    .to_string()
                    .as_bytes(),
                Some("application/json"),
            );
            assert_eq!(result["status"], "degraded");
            assert!(result["evidence"]["body_base64"].is_null());
        }
        for body in [
            br#"{"message":"failed","other":"\\x62earer synthetic_private"}"#.as_slice(),
            br#"{"message":"failed","other":"&#98;earer synthetic_private"}"#.as_slice(),
        ] {
            let result = purchase_response(body, Some("application/json"));
            assert!(result["evidence"]["body_base64"].is_null());
        }
    }
    #[test]
    fn duplicate_json_members_do_not_hide_early_secrets() {
        let body = br#"{"message":"failed","x":{"\u0074oken":"private_value"},"x":0}"#;
        let result = purchase_response(body, Some("application/json"));
        assert!(result["evidence"]["body_base64"].is_null());
        assert!(!result.to_string().contains("private_value"));
        let safe = br#"{"message":"failed","x":1,"x":0}"#;
        assert_eq!(
            STANDARD
                .decode(
                    purchase_response(safe, Some("application/json"))["evidence"]["body_base64"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
            safe
        );
    }
    #[test]
    fn safe_unicode_json_preserves_original_but_escaped_token_is_withheld() {
        let safe = br#"{"title":"\u4e2d"}"#;
        let result = purchase_response(safe, Some("application/json"));
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["body_base64"].as_str().unwrap())
                .unwrap(),
            safe
        );
        let result = purchase_response(
            br#"{"\u0074oken":"private_value"}"#,
            Some("application/json"),
        );
        assert!(result["evidence"]["body_base64"].is_null());
        assert!(!result.to_string().contains("private_value"));
    }
    #[test]
    fn literal_csrf_and_visible_text() {
        let bytes = b"<body>Shuttle 08:00<script>var csrf_token='abc_123';</script></body>";
        let result = parse_page(bytes, Some("text/html"), "page");
        assert_eq!(result["csrf_token_present"], true);
        assert!(result["csrf_token"].is_null());
        assert_eq!(result["visible_page_text"], "Shuttle 08:00");
        assert!(result["availability"].is_null());
        assert!(csrf("var csrf_token='a';var csrf_token='b';").is_none());
    }
    #[test]
    fn purchase_message_is_authority() {
        // A caller-supplied message is an upstream claim, never an order
        // postcondition: the observed key reports the claim and the order
        // state stays unverified either way.
        let success = purchase_response(
            "{\"message\":\"下单成功\",\"status\":0}".as_bytes(),
            Some("application/json"),
        );
        assert_eq!(success["upstream_message_claims_success"], true);
        assert_eq!(success["order_state"], "unverified");
        assert_eq!(success["postcondition_verified"], false);
        let failed = purchase_response(
            b"{\"message\":\"failed\",\"status\":1}",
            Some("application/json"),
        );
        assert_eq!(failed["upstream_message_claims_success"], false);
        assert_eq!(failed["order_state"], "unverified");
        assert_eq!(
            purchase_response(b"{}", Some("application/json"))["status"],
            "degraded"
        );
        let unreviewed = purchase_response(b"{\"message\":\"failed\"}", None);
        assert_eq!(unreviewed["status"], "blocked");
        assert!(unreviewed["evidence"]["body_base64"].is_null());
    }
    #[test]
    fn human_captcha_and_repeated_confirmation_fail_closed() {
        let mut input = json!({"operation":"purchase","date":"2026-10-27","shifts_number":1});
        assert_eq!(
            run(&input.to_string(), false).unwrap()["safety_latched"],
            true
        );
        input["captcha"] = json!("human");
        let preview = run(&input.to_string(), false).unwrap();
        input["intent"] = json!("purchase_shuttle_ticket");
        input["confirm"] = preview["preview_sha256"].clone();
        for _ in 0..2 {
            assert_eq!(run(&input.to_string(), true).unwrap()["submitted"], false);
        }
    }
    #[test]
    fn http_service_never_used() {
        assert_eq!(
            run(r#"{"operation":"service"}"#, false).unwrap()["status"],
            "blocked"
        );
        assert!(AUTH_REASON.contains("HTTP downgrade is prohibited"));
    }
    #[test]
    fn raw_evidence_round_trips() {
        let body = b"ordinary response";
        let result = parse_page(body, Some("text/plain"), "page");
        assert_eq!(result["evidence"]["content_type"], "text/plain");
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["body_base64"].as_str().unwrap())
                .unwrap(),
            body
        );
        let binary = [0xff, 0, 1];
        let result = parse_page(&binary, Some("application/octet-stream"), "page");
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["body_base64"].as_str().unwrap())
                .unwrap(),
            binary
        );
    }
    fn admit_fixture(
        operation: &str,
        status: u16,
        headers: &reqwest::header::HeaderMap,
        bytes: &[u8],
        complete: bool,
    ) -> Value {
        let header_challenge = headers
            .iter()
            .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
        let content_type = response_content_type(headers);
        let mime_reviewed = content_type.is_ok();
        let content_type = content_type.unwrap_or(None);
        let mut assessment =
            response_assessment(status, header_challenge, bytes, content_type, complete);
        if !mime_reviewed && matches!(&assessment, ChallengeAssessment::Clear) {
            assessment = ChallengeAssessment::Unreviewed;
        }
        let challenge = matches!(&assessment, ChallengeAssessment::Detected);
        let mut issued = crate::net::IssuedCookies::new();
        for value in headers.get_all(reqwest::header::SET_COOKIE) {
            issued.absorb(value.to_str().ok());
        }
        live_admission(
            operation,
            LiveResponse {
                status,
                retry: headers.contains_key(reqwest::header::RETRY_AFTER),
                challenge,
                complete,
                issued: &issued,
                credential: None,
                assessment: &assessment,
                bytes,
                content_type,
            },
        )
    }
    #[test]
    fn issued_cookie_admits_ordinary_page_but_withholds_every_echo() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let page_body = b"<body>Shuttle 08:00<script>var csrf_token='abc_123';</script></body>";
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("shuttle=private-value; Path=/; Secure; HttpOnly"),
        );
        let ordinary = admit_fixture("page", 200, &headers, page_body, true);
        assert_eq!(ordinary["status"], "ok");
        assert_eq!(ordinary["visible_page_text"], "Shuttle 08:00");
        assert!(!ordinary.to_string().contains("private-value"));

        for echoed in [
            "private-value".to_owned(),
            STANDARD.encode("shuttle=private-value"),
            STANDARD.encode("private-value"),
        ] {
            let body = format!("<body>{echoed}<script>var csrf_token='abc_123';</script></body>");
            let withheld = admit_fixture("page", 200, &headers, body.as_bytes(), true);
            assert_eq!(withheld["status"], "blocked");
            assert!(withheld.get("visible_page_text").is_none());
            assert!(withheld.get("evidence").is_none());
            assert!(!withheld.to_string().contains("private-value"));
        }

        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("shuttle=\"private-value\"; Path=/; Secure"),
        );
        let encoded_unquoted_pair = STANDARD.encode("shuttle=private-value");
        let body = format!(
            "<body>{encoded_unquoted_pair}<script>var csrf_token='abc_123';</script></body>"
        );
        let withheld = admit_fixture("page", 200, &headers, body.as_bytes(), true);
        assert_eq!(withheld["status"], "blocked");
        assert!(!withheld.to_string().contains("private-value"));

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; session=private-value"),
        );
        let metadata = admit_fixture("page", 200, &headers, page_body, true);
        assert_eq!(metadata["status"], "blocked");
        assert!(metadata.get("evidence").is_none());
        assert!(!metadata.to_string().contains("private-value"));

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("shuttle=; Max-Age=0"));
        let deletion = admit_fixture("page", 200, &headers, page_body, true);
        assert_eq!(deletion["status"], "ok");
        headers.insert(SET_COOKIE, HeaderValue::from_static("malformed"));
        let malformed = admit_fixture("page", 200, &headers, page_body, true);
        assert_eq!(malformed["status"], "blocked");
        assert!(malformed.get("evidence").is_none());
    }
    #[test]
    fn missing_authentication_page_is_not_a_csrf_parse_failure() {
        let body = "<script>alert('未获取到认证信息，请退出后重新进入');history.back()</script>";
        let result = parse_page(body.as_bytes(), Some("text/html"), "page");
        assert_eq!(result["status"], "blocked");
        assert_eq!(result["authentication_required"], true);
        assert_eq!(result["read_only"], true);
        assert_eq!(result["submitted"], false);
        assert_eq!(
            STANDARD
                .decode(result["evidence"]["body_base64"].as_str().unwrap())
                .unwrap(),
            body.as_bytes()
        );
        assert_ne!(
            result["evidence"]["fallback_reason"],
            "missing or ambiguous literal csrf_token assignment"
        );
        let ordinary =
            "<body>未获取到认证信息的旧公告仍可读<script>var csrf_token='abc_123';</script></body>";
        let result = parse_page(ordinary.as_bytes(), Some("text/html"), "page");
        assert_eq!(result["status"], "ok");
        assert!(result.get("authentication_required").is_none());
    }
    #[test]
    fn issued_cookie_html_entity_echo_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("shuttle=private-value"),
        );
        let body = b"<body>&#112;rivate-value<script>var csrf_token='abc_123';</script></body>";
        let result = admit_fixture("page", 200, &headers, body, true);
        assert_eq!(result["status"], "blocked");
        assert!(result.get("visible_page_text").is_none());
        assert!(result.get("evidence").is_none());
        assert!(!result.to_string().contains("private-value"));
    }
    #[test]
    fn issued_cookie_json_escaped_unquoted_value_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid=\"abc/123\""));
        let result = admit_fixture("service", 200, &headers, br#"{"x":"abc\/123"}"#, true);
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
        assert!(!result.to_string().contains("abc/123"));
    }
    #[test]
    fn issued_cookie_duplicate_json_member_echo_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid=abc/123"));
        let result = admit_fixture(
            "service",
            200,
            &headers,
            br#"{"x":"abc\/123","x":"ordinary"}"#,
            true,
        );
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
        assert!(!result.to_string().contains("abc/123"));
    }
    #[test]
    fn issued_cookie_split_node_projection_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("shuttle=private-value"));
        let body = b"<body><span>pri</span><span>vate-value</span><script>var csrf_token='abc_123';</script></body>";
        let result = admit_fixture("page", 200, &headers, body, true);
        assert_eq!(result["status"], "blocked");
        assert!(result.get("visible_page_text").is_none());
        assert!(result.get("evidence").is_none());
    }
    #[test]
    fn issued_cookie_normalized_pair_echo_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid = abc; Path=/"));
        let body = STANDARD.encode("sid=abc");
        let result = admit_fixture("service", 200, &headers, body.as_bytes(), true);
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
    }
    #[test]
    fn issued_cookie_malformed_declarations_fail_closed() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        for declaration in ["sid=\"unterminated", "sid=abc, other=private"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            headers.insert(SET_COOKIE, HeaderValue::from_str(declaration).unwrap());
            let result = admit_fixture("service", 200, &headers, b"ordinary", true);
            assert_eq!(result["status"], "blocked");
            assert!(result.get("evidence").is_none());
        }
    }
    #[test]
    fn issued_cookie_truncated_json_shaped_body_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid=abc/123"));
        let result = admit_fixture("service", 200, &headers, br#"{"x":"abc\/123"#, true);
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
    }
    #[test]
    fn issued_cookie_prefixed_json_escape_is_withheld() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("sid=abc/123"));
        let result = admit_fixture(
            "service",
            200,
            &headers,
            br#"x{"x":"abc\/123"}"#,
            true,
        );
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
    }
    #[test]
    fn denial_cooldown_and_body_failure_survive_cookie_withholding() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER, SET_COOKIE};
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("x=freshopaque123"));
        for status in [401u16, 403] {
            let result = admit_fixture("service", status, &headers, b"freshopaque123", true);
            assert_eq!(result["http_status"], status);
            assert!(
                result["reason"]
                    .as_str()
                    .unwrap()
                    .contains("authentication refused")
            );
            assert!(!result.to_string().contains("freshopaque123"));
        }
        let cooldown = admit_fixture("service", 429, &headers, b"freshopaque123", true);
        assert_eq!(cooldown["http_status"], 429);
        assert_eq!(cooldown["retry_after_present"], false);
        headers.insert(RETRY_AFTER, HeaderValue::from_static("60"));
        let cooldown = admit_fixture("service", 200, &headers, b"freshopaque123", true);
        assert_eq!(
            cooldown["reason"],
            "HTTP cooldown requires operator review; no automatic retry attempted"
        );
        assert_eq!(cooldown["retry_after_present"], true);
        headers.remove(RETRY_AFTER);
        headers.insert("cf-mitigated", HeaderValue::from_static("challenge"));
        let challenge = admit_fixture("page", 200, &headers, b"freshopaque123", true);
        assert!(challenge["reason"].as_str().unwrap().contains("challenge"));
        headers.remove("cf-mitigated");
        let incomplete = admit_fixture("page", 200, &headers, b"freshopaque123", false);
        assert_eq!(
            incomplete["reason"],
            "response incomplete or exceeds byte limit; no subsequent request permitted"
        );
    }
    #[test]
    fn schedule_requires_strict_numeric_route_and_date() {
        for input in [
            json!({"operation":"schedule","date":"2026-11-05","route":0}),
            json!({"operation":"schedule","date":"2026-11-05","route":"1"}),
            json!({"operation":"schedule","date":"2026-13-01","route":1}),
            json!({"operation":"schedule","date":"2026-11-05","route":1,"shifts_number":1}),
        ] {
            assert!(run(&input.to_string(), false).is_err());
        }
        assert!(
            run(
                r#"{"operation":"schedule","date":"2026-11-05","date":"2026-11-06","route":1}"#,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn schedule_observation_states_incomplete_and_never_infers_availability() {
        let body = b"<body>Shuttle service<script>var csrf_token='abc_123';</script></body>";
        let input = json!({"operation":"schedule","date":"2026-11-05","route":7,
            "source":{"body_base64":STANDARD.encode(body),"content_type":"text/html"}});
        let result = run(&input.to_string(), false).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["route"], 7);
        assert_eq!(result["schedule"], json!([]));
        assert_eq!(result["schedule_count"], 0);
        assert_eq!(result["schedule_complete"], false);
        assert_eq!(result["completeness"]["complete"], false);
        assert_eq!(result["completeness"]["list_structure_verified"], false);
        assert_eq!(result["completeness"]["availability_inferred"], false);
        assert_eq!(result["availability"], Value::Null);
        assert_eq!(result["remaining_seats"], Value::Null);
        assert_eq!(result["availability_inferred"], false);
        assert_eq!(result["submitted"], false);
    }
    #[test]
    fn purchase_and_cancel_refuse_without_intent_preview_and_postcondition() {
        let cancel = run(r#"{"operation":"cancel"}"#, false).unwrap();
        assert_eq!(cancel["status"], "unsupported");
        assert_eq!(cancel["refusal_code"], MUTATION_REFUSAL_CODE);
        assert_eq!(cancel["missing_preconditions"], json!(MUTATION_REQUIRED));
        let purchase = run(
            r#"{"operation":"purchase","date":"2026-11-05","shifts_number":1}"#,
            false,
        )
        .unwrap();
        assert_eq!(purchase["status"], "blocked");
        assert_eq!(purchase["refusal_code"], MUTATION_REFUSAL_CODE);
        assert!(
            purchase["missing_preconditions"]
                .as_array()
                .unwrap()
                .contains(&json!("independent_postcondition"))
        );
    }

    fn session_request_json() -> Value {
        json!({
            "authorized": true,
            "username": "synthetic-operator-4b7",
            "password": "synthetic-secret-passphrase",
            "intent": "LOGIN synthetic-operator-4b7 shuttle",
            "read": {"enabled": true, "date": "2026-11-08", "shifts_number": 7}
        })
    }

    /// A network factory that proves the refusal happened before transport:
    /// any call is a test failure because session admission is offline here.
    fn no_network() -> Result<(Client, Governor), Error> {
        panic!("refused input opened network resources")
    }

    #[test]
    fn session_input_admission_is_typed_object_only_and_ordered() {
        let _: fn(&str, bool) -> Result<Value, Error> = session;
        // Disabled returns before date, authorization, intent or credential
        // validation and before transport/admission.
        let mut disabled = session_request_json();
        disabled["authorized"] = json!(false);
        disabled["intent"] = json!("LOGIN other smart classrooms");
        disabled["read"]["enabled"] = json!(false);
        disabled["read"]["date"] = json!("not-a-date");
        disabled["read"]["shifts_number"] = json!(0);
        let result = session_with_network(&disabled.to_string(), false, no_network).unwrap();
        assert_eq!(result["result"], "disabled");
        assert_eq!(result["network_performed"], false);
        assert_eq!(result["write_operations_performed"], false);

        // Non-object roots, unknown/duplicate members and trailing content
        // are all invalid; no credential-bearing Value tree ever exists.
        for input in [
            "[]".to_owned(),
            r#"["a","b"]"#.to_owned(),
            "null".to_owned(),
            format!("{} {{}}", session_request_json()),
            session_request_json()
                .to_string()
                .replace("\"authorized\":true", "\"authorized\":true,\"authorized\":false"),
            session_request_json()
                .to_string()
                .replace("\"authorized\":true", "\"authorized\":true,\"extra\":0"),
        ] {
            assert!(session_with_network(&input, true, no_network).is_err());
        }

        // An enabled read validates the descriptor before authorization.
        for (date, route) in [("2026-13-08", 7), ("2026-11-8", 7), ("2026-11-08", 0)] {
            let mut request = session_request_json();
            request["authorized"] = json!(false);
            request["read"]["date"] = json!(date);
            request["read"]["shifts_number"] = json!(route);
            let error = session_with_network(&request.to_string(), true, no_network).unwrap_err();
            assert_eq!(error.code, "invalid_input");
        }

        // Unauthorized, intent mismatch and offline each refuse before
        // transport or admission, in that order.
        let mut request = session_request_json();
        request["authorized"] = json!(false);
        let error = session_with_network(&request.to_string(), true, no_network).unwrap_err();
        assert_eq!(error.code, "permission");
        let mut request = session_request_json();
        request["intent"] = json!("LOGIN another-operator shuttle");
        let error = session_with_network(&request.to_string(), true, no_network).unwrap_err();
        assert_eq!(error.code, "invalid_input");
        let mut request = session_request_json();
        request["intent"] = json!("LOGIN synthetic-operator-4b7 timetable");
        let error = session_with_network(&request.to_string(), true, no_network).unwrap_err();
        assert_eq!(error.code, "invalid_input");
        let request = session_request_json();
        let error = session_with_network(&request.to_string(), false, no_network).unwrap_err();
        assert_eq!(error.code, "online_required");
    }

    #[test]
    fn session_credential_predicate_screens_body_metadata_and_projection() {
        use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
        let session_secret = |candidate: &[u8]| {
            crate::net::carries_secret(candidate, "synthetic-operator-4b7")
                || crate::net::carries_secret(candidate, "synthetic-secret-passphrase")
                || crate::net::carries_secret(candidate, "session-cookie-private")
                || crate::net::carries_secret(candidate, "abc/def")
        };
        let admit = |headers: &HeaderMap, bytes: &[u8]| {
            let issued = crate::net::IssuedCookies::new();
            let assessment = ChallengeAssessment::Clear;
            live_admission(
                "session",
                LiveResponse {
                    status: 200,
                    retry: false,
                    challenge: false,
                    complete: true,
                    issued: &issued,
                    credential: Some(&session_secret),
                    assessment: &assessment,
                    bytes,
                    content_type: headers
                        .get(CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok()),
                },
            )
        };
        let csrf = "<script>var csrf_token='abc_123';</script>";
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));

        // Ordinary pages still admit with the predicate installed.
        let ordinary = format!("<body>Shuttle 08:00{csrf}</body>");
        let result = admit(&headers, ordinary.as_bytes());
        assert_eq!(result["status"], "ok");
        assert_eq!(result["visible_page_text"], "Shuttle 08:00");

        // Raw literal echoes of the password or a session cookie withhold
        // the body instead of reaching base64 evidence.
        for echoed in ["synthetic-secret-passphrase", "session-cookie-private"] {
            let body = format!("<body>{echoed}{csrf}</body>");
            let result = admit(&headers, body.as_bytes());
            assert_eq!(result["status"], "blocked");
            assert!(result.get("evidence").is_none());
            assert!(!result.to_string().contains(echoed));
        }

        // A secret inside MIME metadata is withheld with its body.
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; note=session-cookie-private"),
        );
        let result = admit(&headers, ordinary.as_bytes());
        assert_eq!(result["status"], "blocked");
        assert!(!result.to_string().contains("session-cookie-private"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // A decoded JSON escape or member spelling of a credential is caught
        // even when the raw bytes never contain the literal secret.
        for body in [
            br#"{"x":"session-cookie-\u0070rivate"}"#.as_slice(),
            br#"{"session-cookie-private":"ordinary"}"#.as_slice(),
            br#"{"x":"session-cookie-private","x":"ordinary"}"#.as_slice(),
        ] {
            let result = admit(&headers, body);
            assert_eq!(result["status"], "blocked");
            assert!(!result.to_string().contains("session-cookie-private"));
        }
        let result = admit(&headers, br#"{"x":"abc/ def"}"#);
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));

        // A credential assembled only inside the decoded projection (split
        // text nodes, compacted whitespace) is still refused.
        let body = format!("<body><span>session-cookie-</span><span>private</span>{csrf}</body>");
        let result = admit(&headers, body.as_bytes());
        assert_eq!(result["status"], "blocked");
        assert!(result.get("visible_page_text").is_none());
        assert!(!result.to_string().contains("session-cookie-private"));

        // Scalar and object-key projection forms match too.
        assert!(credential_echoed_value(&json!("session-cookie-private"), &session_secret));
        assert!(credential_echoed_value(
            &json!({"session-cookie-private": 1}),
            &session_secret
        ));
        assert!(credential_echoed_value(
            &json!("session-cookie- private"),
            &session_secret
        ));
        assert!(!credential_echoed_value(&json!("ordinary"), &session_secret));

        // The upstream missing-authentication page keeps its dedicated
        // result (and therefore the CredentialRejected settle) under the
        // authenticated predicate.
        let missing = "<script>alert('未获取到认证信息，请退出后重新进入');history.back()</script>";
        let result = admit(&headers, missing.as_bytes());
        assert_eq!(result["status"], "blocked");
        assert_eq!(result["authentication_required"], true);
    }

    #[test]
    fn session_credential_html_attribute_entity_is_withheld() {
        let contains = |candidate: &[u8]| crate::net::carries_secret(candidate, "abc/def");
        let issued = crate::net::IssuedCookies::new();
        let assessment = ChallengeAssessment::Clear;
        let result = live_admission(
            "session",
            LiveResponse {
                status: 200,
                retry: false,
                challenge: false,
                complete: true,
                issued: &issued,
                credential: Some(&contains),
                assessment: &assessment,
                bytes: br#"<body data-echo="abc&sol;def">ordinary</body>"#,
                content_type: Some("text/html"),
            },
        );
        assert_eq!(result["status"], "blocked");
        assert!(result.get("evidence").is_none());
        assert!(!result.to_string().contains("abc/def"));
    }

    #[test]
    fn session_credential_html_raw_fallback_uses_the_full_projection() {
        let contains = |candidate: &[u8]| crate::net::carries_secret(candidate, "abc/def");
        for body in [
            "<body>abc/ def</body>",
            "<body>abc/<span>def</span>&amp;</body>",
        ] {
            let issued = crate::net::IssuedCookies::new();
            let assessment = ChallengeAssessment::Clear;
            let result = live_admission(
                "session",
                LiveResponse {
                    status: 200,
                    retry: false,
                    challenge: false,
                    complete: true,
                    issued: &issued,
                    credential: Some(&contains),
                    assessment: &assessment,
                    bytes: body.as_bytes(),
                    content_type: Some("text/html"),
                },
            );
            assert_eq!(result["status"], "blocked", "{body}");
            assert!(result.get("evidence").is_none());
            assert!(!result.to_string().contains("abc/def"));
        }
    }

    #[test]
    fn session_schema_publishes_the_actual_input_byte_limit() {
        assert_eq!(
            schema()["session"]["limits"]["input_utf8_bytes"],
            SESSION_INPUT_LIMIT
        );
    }

    #[test]
    fn session_observation_adds_read_only_provenance_without_rewriting() {
        let observation = session_observation(
            json!({"status":"ok","visible_page_text":"Shuttle 08:00"}),
            "2026-11-08",
            7,
        );
        assert_eq!(observation["operation"], "session");
        assert_eq!(observation["status"], "ok");
        assert_eq!(observation["date"], "2026-11-08");
        assert_eq!(observation["shifts_number"], 7);
        assert_eq!(observation["read_only"], true);
        assert_eq!(observation["submitted"], false);
        assert_eq!(observation["written_requests"], 0);
        assert_eq!(observation["availability_inferred"], false);
        assert_eq!(observation["session_persistent"], false);
        assert_eq!(observation["session_refresh"], false);
        assert_eq!(observation["automatic_retry"], false);
        // A blocked result stays blocked; availability is still not inferred.
        let blocked = session_observation(
            json!({"status":"blocked","reason":"upstream"}),
            "2026-11-08",
            7,
        );
        assert_eq!(blocked["status"], "blocked");
        assert_eq!(blocked["availability_inferred"], false);
    }
}

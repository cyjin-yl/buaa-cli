//! Modern yjsxk existing-session selected-course observation.
//!
//! This is deliberately one read, not a login, CAS callback, mutation, or
//! completeness oracle. Synthetic unit fixtures below are not live evidence.
use super::{deserialize_object, safe_content_type_of, withheld_evidence_parts};
use crate::governor::{FollowupError, Governor, Outcome, RequestKind};
use crate::html::{ChallengeAssessment, assess_challenge_body};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::Cell;
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};

pub(super) const SELECTED_URL: &str =
    "https://yjsxk.buaa.edu.cn/yjsxkapp/sys/xsxkappbuaa/xsxkCourse/loadKbxx.do?sfyx=1&sfjzsyzz=1";
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const SCOPE: &str = "one HTTPS response top-level xkjgList only; requested XNXQDM matches are projected in source order without deduplication or MXMK exclusion; no pagination, account, selection-phase or final-state completeness is inferred";
const OTHER_TERM_SCOPE: &str = "records in that same xkjgList whose string XNXQDM differs from the requested term; other-term rows are counted, not projected";
const MAX_SCALAR_REVIEW: usize = 64 * 1024;
const MAX_REVIEW_DEPTH: usize = 4;

fn blocked(reason: &'static str) -> Value {
    json!({"result":"blocked","reason":reason})
}

/// The protected command owns this string for the whole invocation. Screening
/// borrows every spelling; it never copies a cookie into an ordinary Value.
struct CookieGuard<'a>(&'a str);
impl CookieGuard<'_> {
    fn contains(&self, bytes: &[u8]) -> bool {
        crate::net::carries_secret(bytes, self.0)
            || self
                .0
                .split(';')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .any(|part| {
                    crate::net::carries_secret(bytes, part)
                        || part.split_once('=').is_some_and(|(_, value)| {
                            let value = value.trim();
                            crate::net::carries_secret(bytes, value)
                                || value
                                    .strip_prefix('"')
                                    .and_then(|inner| inner.strip_suffix('"'))
                                    .is_some_and(|unquoted| {
                                        crate::net::carries_secret(bytes, unquoted)
                                    })
                        })
                })
    }
    fn contains_scalar(&self, value: &Value) -> bool {
        crate::net::json_scalar_matches(value, |bytes| self.contains(bytes))
    }

    fn sensitive_text(&self, value: &str) -> bool {
        self.review_text(value, 0, &Cell::new(MAX_SCALAR_REVIEW))
    }

    fn review_text(&self, value: &str, depth: usize, remaining: &Cell<usize>) -> bool {
        if depth > MAX_REVIEW_DEPTH || value.len() > remaining.get() {
            return true;
        }
        remaining.set(remaining.get() - value.len());
        if self.contains(value.as_bytes()) || crate::net::sensitive_text_marker(value) {
            return true;
        }
        let has_percent = value.as_bytes().contains(&b'%');
        let has_plus = value.as_bytes().contains(&b'+');
        if has_percent || has_plus {
            let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
            for plus_as_space in [false, true] {
                if (plus_as_space && !has_plus) || (!plus_as_space && !has_percent) {
                    continue;
                }
                decoded.fill(0);
                decoded.clear();
                crate::net::percent_decode_into(value.as_bytes(), plus_as_space, &mut decoded);
                if decoded.as_slice() != value.as_bytes()
                    && self.review_decoded(&decoded, depth + 1, remaining)
                {
                    return true;
                }
            }
        }
        // An outer encoding must not conceal a nested JSON/HTML/MIME grammar.
        let trimmed = value.trim();
        if trimmed.len() >= 4
            && trimmed.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
            })
        {
            let compact = trimmed
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
                .then(|| {
                    let mut compact = Zeroizing::new(Vec::with_capacity(trimmed.len()));
                    compact.extend(trimmed.bytes().filter(|byte| !byte.is_ascii_whitespace()));
                    compact
                });
            let encoded = compact
                .as_ref()
                .map_or(trimmed.as_bytes(), |value| value.as_slice());
            if encoded.len() >= 4 && encoded.len() % 4 != 1 {
                let url_alphabet = encoded.iter().any(|&byte| matches!(byte, b'-' | b'_'));
                let padded = encoded.last() == Some(&b'=');
                let engine = match (url_alphabet, padded) {
                    (false, true) => &STANDARD,
                    (false, false) => &STANDARD_NO_PAD,
                    (true, true) => &URL_SAFE,
                    (true, false) => &URL_SAFE_NO_PAD,
                };
                let mut decoded = Zeroizing::new(Vec::with_capacity(encoded.len() / 4 * 3 + 3));
                if engine.decode_vec(encoded, &mut decoded).is_ok()
                    && self.review_decoded(&decoded, depth + 1, remaining)
                {
                    return true;
                }
            }
        }
        if matches!(trimmed.as_bytes().first(), Some(b'{' | b'[' | b'"')) {
            // Visit every occurrence, including duplicate members. Building a
            // Value first could discard a credential hidden in an earlier one.
            let mut decoder = serde_json::Deserializer::from_str(trimmed);
            return serde::de::DeserializeSeed::deserialize(
                ScalarReview {
                    cookie: self,
                    depth: depth + 1,
                    remaining,
                },
                &mut decoder,
            )
            .and_then(|()| decoder.end())
            .is_err();
        }
        // Native identifier scalars have no reviewed MIME encoded-word, HTML
        // or free-standing escape grammar. A negative finite-pattern match is
        // not evidence that those representations are credential-free.
        value.contains("=?")
            || value.contains('<')
            || value.contains('&')
            || value.contains('\\')
            || value.chars().any(char::is_control)
    }

    fn review_decoded(&self, value: &[u8], depth: usize, remaining: &Cell<usize>) -> bool {
        if self.contains(value) {
            return true;
        }
        // Plain identifiers may also be base64-alphabet strings. Inspect the
        // bytes for echoes; only UTF-8 results introduce a supported text
        // grammar. No interpretation of binary data is projected.
        std::str::from_utf8(value).is_ok_and(|text| self.review_text(text, depth, remaining))
    }
}

#[derive(Clone, Copy)]
struct ScalarReview<'a, 'cookie> {
    cookie: &'a CookieGuard<'cookie>,
    depth: usize,
    remaining: &'a Cell<usize>,
}
impl ScalarReview<'_, '_> {
    fn child<E: serde::de::Error>(self) -> Result<Self, E> {
        if self.depth >= MAX_REVIEW_DEPTH {
            return Err(E::custom("nested credential inspection is unreviewed"));
        }
        Ok(Self {
            depth: self.depth + 1,
            ..self
        })
    }
    fn scalar<E: serde::de::Error>(self, value: Value) -> Result<(), E> {
        if self.cookie.contains_scalar(&value) {
            Err(E::custom("encoded credential scalar is withheld"))
        } else {
            Ok(())
        }
    }
}
impl<'de> serde::de::DeserializeSeed<'de> for ScalarReview<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for ScalarReview<'_, '_> {
    type Value = ();
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded credential-reviewed JSON value")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        if self.cookie.review_text(value, self.depth, self.remaining) {
            Err(E::custom(
                "encoded or unreviewed credential text is withheld",
            ))
        } else {
            Ok(())
        }
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<(), E> {
        self.visit_str(&Zeroizing::new(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.scalar(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<(), E> {
        self.scalar(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<(), E> {
        self.scalar(Value::Number(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<(), E> {
        self.scalar(Value::Number(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<(), E> {
        let value = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite credential scalar"))?;
        self.scalar(Value::Number(value))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_element_seed(self.child()?)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut fields: A) -> Result<(), A::Error> {
        while fields.next_key_seed(self.child()?)?.is_some() {
            fields.next_value_seed(self.child()?)?;
        }
        Ok(())
    }
}

fn optional_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

/// Only scalar native roles are admitted. Missing/null stays null; a number is
/// never silently stringified and an object/array/bool is unreviewed structure.
enum NativeScalar {
    String(Zeroizing<String>),
    Number(serde_json::Number),
}
impl NativeScalar {
    fn into_value(self) -> Value {
        match self {
            Self::String(mut value) => Value::String(std::mem::take(&mut *value)),
            Self::Number(value) => Value::Number(value),
        }
    }
    fn sensitive(&self, cookie: &CookieGuard<'_>) -> bool {
        match self {
            Self::String(value) => cookie.sensitive_text(value),
            Self::Number(value) => cookie.contains_scalar(&Value::Number(value.clone())),
        }
    }
}
impl<'de> Deserialize<'de> for NativeScalar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Scalar;
        impl<'de> serde::de::Visitor<'de> for Scalar {
            type Value = NativeScalar;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string or number")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(NativeScalar::String(Zeroizing::new(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(NativeScalar::String(Zeroizing::new(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(NativeScalar::Number(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(NativeScalar::Number(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(NativeScalar::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
        }
        deserializer.deserialize_any(Scalar)
    }
}

struct SourceRecord {
    bjdm: Option<NativeScalar>,
    xnxqdm: Option<NativeScalar>,
    wid: Option<NativeScalar>,
    yyz: Option<NativeScalar>,
}
impl<'de> Deserialize<'de> for SourceRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "BJDM")]
            bjdm: Option<NativeScalar>,
            #[serde(rename = "XNXQDM")]
            xnxqdm: Option<NativeScalar>,
            #[serde(rename = "WID")]
            wid: Option<NativeScalar>,
            #[serde(rename = "YYZ")]
            yyz: Option<NativeScalar>,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            bjdm: raw.bjdm,
            xnxqdm: raw.xnxqdm,
            wid: raw.wid,
            yyz: raw.yyz,
        })
    }
}

struct SourceResponse {
    xkjg_list: Option<Vec<SourceRecord>>,
    msg: Option<Zeroizing<String>>,
    message: Option<Zeroizing<String>>,
}
impl<'de> Deserialize<'de> for SourceResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "xkjgList")]
            xkjg_list: Option<Vec<SourceRecord>>,
            #[serde(default, deserialize_with = "optional_secret")]
            msg: Option<Zeroizing<String>>,
            #[serde(default, deserialize_with = "optional_secret")]
            message: Option<Zeroizing<String>>,
        }
        let raw: Raw = deserialize_object(deserializer)?;
        Ok(Self {
            xkjg_list: raw.xkjg_list,
            msg: raw.msg,
            message: raw.message,
        })
    }
}

fn denied_message(message: &str) -> bool {
    matches!(
        message.trim(),
        "请重新登录"
            | "请先登录"
            | "未登录"
            | "登录已失效"
            | "登录已过期"
            | "会话已过期"
            | "会话失效"
            | "not logged in"
            | "session expired"
            | "unauthorized"
    )
}

fn body_rejects_session(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Messages {
        #[serde(default, deserialize_with = "optional_secret")]
        msg: Option<Zeroizing<String>>,
        #[serde(default, deserialize_with = "optional_secret")]
        message: Option<Zeroizing<String>>,
    }
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let messages: Result<Messages, _> = deserialize_object(&mut decoder);
    let Ok(messages) = messages else {
        return false;
    };
    decoder.end().is_ok()
        && [messages.msg.as_deref(), messages.message.as_deref()]
            .into_iter()
            .flatten()
            .any(|message| denied_message(message))
}

enum ProjectionError {
    SessionRejected,
    Unreviewed(&'static str),
    Privacy,
}

fn projected_cookie(value: &Value, cookie: &CookieGuard<'_>) -> bool {
    match value {
        Value::String(text) => cookie.contains(text.as_bytes()),
        Value::Array(values) => values.iter().any(|value| projected_cookie(value, cookie)),
        Value::Object(fields) => fields.values().any(|value| projected_cookie(value, cookie)),
        Value::Number(_) | Value::Bool(_) | Value::Null => cookie.contains_scalar(value),
    }
}

fn wipe_projection(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_projection),
        Value::Object(fields) => {
            for (mut key, mut value) in std::mem::take(fields) {
                key.zeroize();
                wipe_projection(&mut value);
            }
        }
        _ => {}
    }
}

fn project(
    source: SourceResponse,
    requested_term: &str,
    cookie: &CookieGuard<'_>,
) -> Result<Value, ProjectionError> {
    let messages = [source.msg.as_deref(), source.message.as_deref()];
    if messages
        .into_iter()
        .flatten()
        .any(|message| cookie.contains(message.as_bytes()))
    {
        return Err(ProjectionError::Privacy);
    }
    if messages
        .into_iter()
        .flatten()
        .any(|message| denied_message(message))
    {
        return Err(ProjectionError::SessionRejected);
    }
    // No source contract establishes arbitrary message text as success. An
    // unrecognized nonempty message therefore cannot accompany a claimed list.
    if messages
        .into_iter()
        .flatten()
        .any(|message| !message.trim().is_empty())
    {
        return Err(ProjectionError::Unreviewed(
            "yjsxk response message semantics are unreviewed",
        ));
    }
    let rows = source.xkjg_list.ok_or(ProjectionError::Unreviewed(
        "top-level xkjgList array is missing or null",
    ))?;
    if rows.iter().any(|row| {
        [&row.bjdm, &row.xnxqdm, &row.wid, &row.yyz]
            .into_iter()
            .flatten()
            .any(|value| value.sensitive(cookie))
    }) {
        return Err(ProjectionError::Privacy);
    }
    let source_record_count = rows.len();
    let mut records = Vec::new();
    let mut other_term_count = 0usize;
    let mut unscoped_record_count = 0usize;
    for (source_index, row) in rows.into_iter().enumerate() {
        let SourceRecord {
            bjdm,
            xnxqdm,
            wid,
            yyz,
        } = row;
        match xnxqdm {
            Some(NativeScalar::String(mut term)) if term.as_str() == requested_term => {
                let mut record = serde_json::Map::new();
                record.insert("source_index".into(), Value::from(source_index));
                record.insert(
                    "BJDM".into(),
                    bjdm.map_or(Value::Null, NativeScalar::into_value),
                );
                record.insert("XNXQDM".into(), Value::String(std::mem::take(&mut *term)));
                record.insert(
                    "WID".into(),
                    wid.map_or(Value::Null, NativeScalar::into_value),
                );
                record.insert(
                    "YYZ".into(),
                    yyz.map_or(Value::Null, NativeScalar::into_value),
                );
                records.push(Value::Object(record));
            }
            Some(NativeScalar::String(_)) => other_term_count += 1,
            Some(NativeScalar::Number(_)) => {
                return Err(ProjectionError::Unreviewed(
                    "XNXQDM must be a string or null; numeric term identity is unreviewed",
                ));
            }
            None => unscoped_record_count += 1,
        }
    }
    let requested_term_match_count = records.len();
    let mut output = json!({
        "kind":"yjsxk_selected_courses",
        "application":"yjsxk",
        "operation":"selected",
        "requested_xnxqdm":requested_term,
        "scope":SCOPE,
        "source_collection":"xkjgList",
        "source_record_count":source_record_count,
        "source_collection_observed_empty":source_record_count == 0,
        "requested_term_match_count":requested_term_match_count,
        "other_term_count":other_term_count,
        "other_term_scope":OTHER_TERM_SCOPE,
        "unscoped_record_count":unscoped_record_count,
        "unscoped_record_scope":"records in the same xkjgList with missing/null XNXQDM; neither requested nor other-term membership is inferred",
        "records":null,
        "account_identity_verified":false,
        "completeness":"unknown",
        "mutation_allowed":false,
        "current_app_authenticity":"not_asserted",
        "current_account_rights":"not_asserted",
        "final_postcondition":false,
        "absence_proves_withdrawal":false,
    });
    output["records"] = Value::Array(records);
    if projected_cookie(&output, cookie) {
        wipe_projection(&mut output);
        return Err(ProjectionError::Privacy);
    }
    Ok(output)
}

struct Admission {
    output: Value,
    credential_rejected: bool,
    challenge: bool,
    network_failure: bool,
}

struct Observation<'a> {
    status: u16,
    content_type: Option<&'a str>,
    retry_present: bool,
    redirect: bool,
    issued_cookie: bool,
    header_challenge: bool,
    header_echo: bool,
    read_failed: bool,
    declared_oversize: bool,
    body: &'a [u8],
}

fn admit(
    observation: Observation<'_>,
    requested_term: &str,
    cookie: &CookieGuard<'_>,
) -> Admission {
    let Observation {
        status,
        content_type,
        retry_present,
        redirect,
        issued_cookie,
        header_challenge,
        header_echo,
        read_failed,
        declared_oversize,
        body,
    } = observation;
    let network_failure = read_failed || declared_oversize || body.len() > super::LIMIT;
    let complete = !network_failure;
    let assessment = assess_challenge_body(body, content_type, complete);
    let challenge = header_challenge || assessment == ChallengeAssessment::Detected;
    let raw_echo = header_echo
        || cookie.contains(body)
        || content_type.is_some_and(|value| cookie.contains(value.as_bytes()));
    // Even an allowlisted MIME essence is unnecessary when Set-Cookie or a
    // metadata echo already makes response privacy admission fail closed.
    let safe_mime = (!issued_cookie && !raw_echo)
        .then(|| safe_content_type_of(content_type))
        .flatten();
    let evidence = |reason: &'static str| withheld_evidence_parts(status, safe_mime, body, reason);
    let refuse = |reason: &'static str| Admission {
        output: json!({"result":"blocked","reason":reason,"evidence":evidence(reason)}),
        credential_rejected: !challenge
            && !network_failure
            && (matches!(status, 401 | 403)
                || (safe_content_type_of(content_type) == Some("application/json")
                    && body_rejects_session(body))),
        challenge,
        network_failure,
    };
    if network_failure {
        return refuse(
            "yjsxk response body did not complete within the bounded read; no retry performed",
        );
    }
    if challenge {
        return refuse("yjsxk response challenge detected; no login, redirect or retry performed");
    }
    if assessment == ChallengeAssessment::Unreviewed {
        return refuse(
            "yjsxk response challenge assessment is unreviewed; admission refused without a confirmed challenge",
        );
    }
    if issued_cookie {
        return refuse(
            "yjsxk response issued Set-Cookie; this fixed-cookie reader has no reviewed cookie adoption and withheld the response",
        );
    }
    if redirect {
        return refuse(
            "yjsxk redirect or Location response refused; no downgrade, CAS callback, login, follow-up or retry performed",
        );
    }
    if retry_present {
        return refuse(
            "yjsxk response supplied Retry-After; cooldown retained and no retry performed",
        );
    }
    if matches!(status, 401 | 403) {
        return refuse("yjsxk existing session was rejected; no login or retry performed");
    }
    if status != 200 {
        return refuse(
            "yjsxk selected read requires one HTTP 200 response; no fallback or retry performed",
        );
    }
    if raw_echo {
        return refuse(
            "yjsxk response contains a submitted cookie/header/value echo; response admission refused",
        );
    }
    if safe_mime != Some("application/json") {
        return Admission {
            output: json!({"result":"parsed","data":evidence("yjsxk selected read did not declare exactly one application/json Content-Type")}),
            credential_rejected: false,
            challenge,
            network_failure,
        };
    }
    let source = match serde_json::from_slice::<SourceResponse>(body) {
        Ok(source) => source,
        Err(_) if body_rejects_session(body) => {
            return Admission {
                output: json!({"result":"blocked","reason":"yjsxk application rejected the existing session; no login or retry performed","evidence":evidence("authenticated session rejection body withheld")}),
                credential_rejected: true,
                challenge,
                network_failure,
            };
        }
        Err(_) => {
            return Admission {
                output: json!({"result":"parsed","data":evidence("yjsxk response is not one admitted JSON object with source-shaped scalar records")}),
                credential_rejected: false,
                challenge,
                network_failure,
            };
        }
    };
    match project(source, requested_term, cookie) {
        Ok(data) => {
            let mut output = json!({"result":"completed","data":null});
            output["data"] = data;
            Admission {
                output,
                credential_rejected: false,
                challenge,
                network_failure,
            }
        }
        Err(ProjectionError::SessionRejected) => Admission {
            output: json!({"result":"blocked","reason":"yjsxk application rejected the existing session; no login or retry performed","evidence":evidence("authenticated session rejection body withheld")}),
            credential_rejected: true,
            challenge,
            network_failure,
        },
        Err(ProjectionError::Unreviewed(reason)) => Admission {
            output: json!({"result":"parsed","data":evidence(reason)}),
            credential_rejected: false,
            challenge,
            network_failure,
        },
        Err(ProjectionError::Privacy) => refuse(
            "yjsxk projected scalar credential inspection refused or remains unreviewed; projection withheld",
        ),
    }
}

struct Client {
    http: reqwest::blocking::Client,
    governor: Governor,
    cookie: Zeroizing<String>,
}
impl Client {
    fn new(cookie: Zeroizing<String>) -> Result<Self, Value> {
        if !crate::net::valid_session_cookie(&cookie) {
            return Err(blocked(
                "invalid yjsxk protected-stdin session_cookie syntax",
            ));
        }
        let http = reqwest::blocking::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .user_agent("buaa-cli/0.1")
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(DEADLINE)
            .build()
            .map_err(|_| blocked("cannot initialize strict-TLS yjsxk HTTPS client"))?;
        let governor = Governor::open()
            .map_err(|_| blocked("shared governor unavailable; yjsxk request not sent"))?;
        Ok(Self {
            http,
            governor,
            cookie,
        })
    }

    fn selected(&self, requested_term: &str) -> Value {
        let mut cookie = match reqwest::header::HeaderValue::from_str(&self.cookie) {
            Ok(cookie) => cookie,
            Err(_) => return blocked("invalid yjsxk session Cookie header; request not sent"),
        };
        cookie.set_sensitive(true);
        let mut lease = match self.governor.try_acquire(RequestKind::Interactive) {
            Ok(lease) => lease,
            Err(_) => {
                return blocked("shared governor denied yjsxk request admission; request not sent");
            }
        };
        let request = self
            .http
            .get(SELECTED_URL)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(reqwest::header::COOKIE, cookie)
            .timeout(DEADLINE);
        let mut response = match lease.start_request(|| request.send()) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                if lease.finish(Outcome::NetworkFailure).is_err() {
                    return blocked(
                        "yjsxk network failed and shared governor settlement failed; no retry performed",
                    );
                }
                return blocked("yjsxk request failed before HTTP headers; no retry performed");
            }
            Err(FollowupError::Governor(_)) => {
                return blocked(
                    "shared governor request-start admission failed; yjsxk request not sent and pending outcome retained",
                );
            }
        };
        let status = response.status().as_u16();
        // Inspect the complete raw header block before consuming any body. No
        // raw header value, Location or Set-Cookie is copied into output.
        let header_challenge = response
            .headers()
            .iter()
            .any(|(name, value)| crate::net::challenge_header(name.as_str(), value.as_bytes()));
        let issued_cookie = crate::net::issues_session_cookie(response.headers());
        let retry_present = response
            .headers()
            .contains_key(reqwest::header::RETRY_AFTER);
        let redirect = (300..400).contains(&status)
            || response.headers().contains_key(reqwest::header::LOCATION);
        let guard = CookieGuard(&self.cookie);
        let header_echo = response.headers().iter().any(|(name, value)| {
            guard.contains(name.as_str().as_bytes()) || guard.contains(value.as_bytes())
        });
        if lease
            .observe_http_many(
                status,
                response
                    .headers()
                    .get_all(reqwest::header::RETRY_AFTER)
                    .iter()
                    .map(|value| value.to_str().ok()),
                header_challenge,
            )
            .is_err()
        {
            return blocked(
                "cannot persist yjsxk response headers in the shared governor; body admission refused",
            );
        }
        let mut content_type_values = response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter();
        let content_type = content_type_values
            .next()
            .and_then(|value| value.to_str().ok())
            .filter(|_| content_type_values.next().is_none())
            .map(|value| Zeroizing::new(value.to_owned()));
        let declared_oversize = response
            .content_length()
            .is_some_and(|length| length > super::LIMIT as u64);
        // This allocation never grows, and its full initialized length stays
        // zeroizing even after a failed read writes an unreported partial tail.
        let mut body = Zeroizing::new(vec![0u8; super::LIMIT + 1]);
        let mut used = 0usize;
        let mut read_failed = false;
        loop {
            match response.read(&mut body[used..]) {
                Ok(0) => break,
                Ok(count) => {
                    used += count;
                    if used > super::LIMIT {
                        break;
                    }
                }
                Err(_) => {
                    read_failed = true;
                    break;
                }
            }
        }
        let admission = admit(
            Observation {
                status,
                content_type: content_type.as_deref().map(String::as_str),
                retry_present,
                redirect,
                issued_cookie,
                header_challenge,
                header_echo,
                read_failed,
                declared_oversize,
                body: &body[..used],
            },
            requested_term,
            &guard,
        );
        let settled = if admission.credential_rejected {
            lease.finish(Outcome::CredentialRejected)
        } else {
            // observe_http_many already retained every valid deadline and
            // malformed/missing 429 floor; this final field cannot shorten it.
            lease.finish(Outcome::Http {
                status,
                retry_after: response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                challenge: admission.challenge,
                network_failure: admission.network_failure,
            })
        };
        if settled.is_err() {
            return blocked(
                "cannot settle yjsxk request in the shared governor; projected response withheld",
            );
        }
        admission.output
    }
}

pub(super) fn selected(cookie: Zeroizing<String>, requested_term: &str) -> Value {
    match Client::new(cookie) {
        Ok(client) => client.selected(requested_term),
        Err(output) => output,
    }
}

pub(super) fn schema() -> Value {
    json!({
        "operation":"selected",
        "application":"yjsxk",
        "url":SELECTED_URL,
        "method":"GET",
        "maximum_requests_per_invocation":1,
        "redirects":false,
        "retries":false,
        "login":false,
        "proxy":false,
        "tls":"strict_https_only",
        "overall_deadline_seconds":30,
        "body_limit":super::LIMIT,
        "session_cookie":"protected stdin only; zeroizing typed storage; full header and every value screened; never logged, persisted, cached or projected",
        "set_cookie":"refused without adoption",
        "input":{"type":"object","additionalProperties":false,"required":["operation","application","xnxqdm","authorized","session_cookie"],"properties":{
            "operation":{"const":"selected"},
            "application":{"const":"yjsxk"},
            "xnxqdm":{"type":"string","pattern":"^[0-9]{5}$"},
            "authorized":{"const":true},
            "session_cookie":{"type":"string","writeOnly":true}
        }},
        "output":{"type":"object","additionalProperties":false,"required":[
            "kind","application","operation","requested_xnxqdm","scope","source_collection","source_record_count",
            "source_collection_observed_empty","requested_term_match_count","other_term_count","other_term_scope",
            "unscoped_record_count","unscoped_record_scope","records","account_identity_verified","completeness",
            "mutation_allowed","current_app_authenticity","current_account_rights","final_postcondition","absence_proves_withdrawal"
        ],"properties":{
            "kind":{"const":"yjsxk_selected_courses"},
            "application":{"const":"yjsxk"},
            "operation":{"const":"selected"},
            "requested_xnxqdm":{"type":"string","pattern":"^[0-9]{5}$"},
            "scope":{"const":SCOPE},
            "source_collection":{"const":"xkjgList"},
            "source_record_count":{"type":"integer","minimum":0},
            "source_collection_observed_empty":{"type":"boolean"},
            "requested_term_match_count":{"type":"integer","minimum":0},
            "other_term_count":{"type":"integer","minimum":0},
            "other_term_scope":{"const":OTHER_TERM_SCOPE},
            "unscoped_record_count":{"type":"integer","minimum":0},
            "unscoped_record_scope":{"type":"string"},
            "records":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["source_index","BJDM","XNXQDM","WID","YYZ"],"properties":{
                "source_index":{"type":"integer","minimum":0},
                "BJDM":{"type":["string","number","null"]},
                "XNXQDM":{"type":"string"},
                "WID":{"type":["string","number","null"]},
                "YYZ":{"type":["string","number","null"]}
            }}},
            "account_identity_verified":{"const":false},
            "completeness":{"const":"unknown"},
            "mutation_allowed":{"const":false},
            "current_app_authenticity":{"const":"not_asserted"},
            "current_account_rights":{"const":"not_asserted"},
            "final_postcondition":{"const":false},
            "absence_proves_withdrawal":{"const":false}
        }},
        "source_roles":"BJDM, XNXQDM, WID and YYZ retain separate native source roles; WID is not BJDM, a course WID, or IEAS rwh; YYZ is not an IEAS category",
        "term_identity":"xnxqdm is the exact five-digit yjsxk XNXQDM filter, not IEAS page_xnxq/pageXnxq and not the historical academic-year-season spelling",
        "unverified":["authenticated account identity and current application authenticity","account-specific read rights","xkjgList pagination and complete selected-state scope","selection phase","withdrawal from absence","all mutation and postcondition semantics"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(body: &[u8]) -> Observation<'_> {
        Observation {
            status: 200,
            content_type: Some("application/json; charset=utf-8"),
            retry_present: false,
            redirect: false,
            issued_cookie: false,
            header_challenge: false,
            header_echo: false,
            read_failed: false,
            declared_oversize: false,
            body,
        }
    }

    fn synthetic(body: &str, cookie: &str) -> Admission {
        // Synthetic bytes only: this is a consumer-boundary fixture, not a
        // campus capture or evidence of deployment response semantics.
        admit(observation(body.as_bytes()), "20261", &CookieGuard(cookie))
    }

    #[test]
    fn source_roles_other_terms_duplicates_and_missing_facts_are_preserved() {
        let body = r#"{"xkjgList":[
            {"BJDM":"A","XNXQDM":"20261","WID":"row-one","YYZ":1,"rwh":"never-project"},
            {"BJDM":"A","XNXQDM":"20261","WID":"row-one","YYZ":1},
            {"BJDM":"MXMK-synthetic","XNXQDM":"20261"},
            {"BJDM":"other","XNXQDM":"20262","WID":99,"YYZ":"2"},
            {"BJDM":"unscoped","XNXQDM":null,"WID":null,"YYZ":null}
        ]}"#;
        let admission = synthetic(body, "sid=synthetic-cookie");
        assert_eq!(admission.output["result"], "completed");
        let data = &admission.output["data"];
        assert_eq!(data["source_record_count"], 5);
        assert_eq!(data["requested_term_match_count"], 3);
        assert_eq!(data["other_term_count"], 1);
        assert_eq!(data["unscoped_record_count"], 1);
        let rows = data["records"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        for role in ["BJDM", "XNXQDM", "WID", "YYZ"] {
            assert_eq!(
                rows[0][role], rows[1][role],
                "duplicate native source roles must remain distinct array entries"
            );
        }
        assert_eq!(rows[0]["source_index"], 0);
        assert_eq!(rows[1]["source_index"], 1);
        assert_eq!(
            rows[2]["BJDM"], "MXMK-synthetic",
            "historical client display exclusion is not a read filter"
        );
        assert_eq!(rows[2]["WID"], Value::Null);
        assert_eq!(rows[2]["YYZ"], Value::Null);
        assert_eq!(rows[0]["WID"], "row-one");
        assert_eq!(rows[0]["YYZ"], 1);
        assert!(rows[0].get("rwh").is_none());
        assert_eq!(data["account_identity_verified"], false);
        assert_eq!(data["completeness"], "unknown");
        assert_eq!(data["mutation_allowed"], false);
        assert_eq!(data["current_app_authenticity"], "not_asserted");
        assert_eq!(data["current_account_rights"], "not_asserted");
        assert_eq!(data["final_postcondition"], false);
    }

    #[test]
    fn missing_collection_is_not_success_and_empty_is_explicitly_incomplete() {
        for body in [
            r#"{"data":[]}"#,
            r#"{"xkjgList":null}"#,
            r#"[]"#,
            r#"{"xkjgList":[],"xkjgList":[]}"#,
            r#"{"xkjgList":[["A","20261"]]}"#,
            r#"{"xkjgList":[{"BJDM":{},"XNXQDM":"20261"}]}"#,
            r#"{"xkjgList":[{"XNXQDM":20261}]}"#,
        ] {
            let admission = synthetic(body, "sid=synthetic-cookie");
            assert_eq!(admission.output["result"], "parsed");
            assert_eq!(admission.output["data"]["kind"], "fallback");
            assert_eq!(admission.output["data"]["body_withheld"], true);
            assert!(admission.output["data"].get("body_base64").is_none());
            assert!(admission.output["data"].get("records").is_none());
        }
        let admission = synthetic(r#"{"xkjgList":[]}"#, "sid=synthetic-cookie");
        assert_eq!(admission.output["result"], "completed");
        let data = &admission.output["data"];
        assert_eq!(data["source_collection_observed_empty"], true);
        assert_eq!(data["requested_term_match_count"], 0);
        assert_eq!(data["completeness"], "unknown");
        assert_eq!(data["final_postcondition"], false);
        assert_eq!(data["absence_proves_withdrawal"], false);
    }

    #[test]
    fn full_header_each_value_and_encoded_scalar_echoes_are_refused() {
        let cookie = "sid=abc_123; wish=~~~???x";
        let full_header = STANDARD.encode(cookie);
        let cases = [
            format!(r#"{{"xkjgList":[{{"BJDM":"{full_header}","XNXQDM":"20261"}}]}}"#),
            r#"{"xkjgList":[{"BJDM":"abc%5F123","XNXQDM":"20261"}]}"#.to_string(),
            r#"{"xkjgList":[{"WID":"abc\u005f123","XNXQDM":"20261"}]}"#.to_string(),
            r#"{"xkjgList":[{"BJDM":"%66n5+Pz8/eA==","XNXQDM":"20261"}]}"#.to_string(),
            r#"{"xkjgList":[{"BJDM":"csrfToken=synthetic","XNXQDM":"20261"}]}"#.to_string(),
        ];
        for body in cases {
            let admission = synthetic(&body, cookie);
            assert_eq!(admission.output["result"], "blocked", "{body}");
            assert!(
                admission.output["reason"]
                    .as_str()
                    .unwrap()
                    .contains("refused")
                    || admission.output["reason"]
                        .as_str()
                        .unwrap()
                        .contains("echo")
            );
            assert_eq!(admission.output["evidence"]["body_withheld"], true);
            assert!(!admission.output.to_string().contains("abc_123"));
            assert!(!admission.output.to_string().contains("~~~???x"));
            assert!(admission.output["evidence"].get("body_base64").is_none());
        }
        let numeric = synthetic(
            r#"{"xkjgList":[{"BJDM":987654321,"XNXQDM":"20261"}]}"#,
            "sid=987654321",
        );
        assert_eq!(numeric.output["result"], "blocked");
        assert!(!numeric.output.to_string().contains("987654321"));
        let normalized: Value = serde_json::from_str("1e9").unwrap();
        let numeric_cookie = format!("sid={normalized}");
        let normalized_echo = synthetic(
            r#"{"xkjgList":[{"YYZ":1e9,"XNXQDM":"20261"}]}"#,
            &numeric_cookie,
        );
        assert_eq!(normalized_echo.output["result"], "blocked");
        let mut observed = observation(br#"{"xkjgList":[]}"#);
        observed.content_type = Some("application/json; session=abc_123");
        let metadata = admit(observed, "20261", &CookieGuard(cookie));
        assert_eq!(metadata.output["result"], "blocked");
        assert_eq!(metadata.output["evidence"]["content_type"], Value::Null);
        assert!(!metadata.output.to_string().contains("abc_123"));
    }

    #[test]
    fn nested_or_unreviewed_scalar_encodings_never_expose_cookie_values() {
        let escaped = format!(r#"{{"v":"abc{}u005f123"}}"#, char::from(0x5c));
        let repeated = format!(
            r#"{{"v":"abc{}u005f123","v":"ordinary"}}"#,
            char::from(0x5c),
        );
        let wrapped = STANDARD.encode(&escaped);
        let spaced = format!(" {wrapped} ");
        let folded = wrapped
            .as_bytes()
            .chunks(4)
            .map(|bytes| std::str::from_utf8(bytes).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let mime_wrapped = STANDARD.encode("=?UTF-8?Q?abc=5F123?=");
        for encoded in [
            escaped.as_str(),
            repeated.as_str(),
            wrapped.as_str(),
            spaced.as_str(),
            folded.as_str(),
            mime_wrapped.as_str(),
            "=?UTF-8?Q?abc=5F123?=",
            "abc&#95;123",
            "abc%26%2395%3B123",
            "eyJ2IjoiYWJjXzEyMyJ9",
        ] {
            for role in ["BJDM", "WID", "YYZ"] {
                let mut body = json!({"xkjgList":[{"XNXQDM":"20261"}]});
                body["xkjgList"][0][role] = json!(encoded);
                let admission = synthetic(&body.to_string(), "sid=abc_123");
                assert_eq!(admission.output["result"], "blocked");
                assert_eq!(admission.output["evidence"]["body_withheld"], true);
                assert!(admission.output["evidence"].get("body_base64").is_none());
                assert!(admission.output.get("data").is_none());
            }
        }
        let ordinary = r#"{"v":"ordinary"}"#;
        let wrapped_ordinary = STANDARD.encode(ordinary);
        let spaced_ordinary = format!(" {wrapped_ordinary} ");
        for ordinary in [
            ordinary,
            wrapped_ordinary.as_str(),
            spaced_ordinary.as_str(),
        ] {
            let body = json!({"xkjgList":[{"XNXQDM":"20261","BJDM":ordinary}]});
            let admission = synthetic(&body.to_string(), "sid=abc_123");
            assert_eq!(admission.output["result"], "completed");
            assert_eq!(admission.output["data"]["records"][0]["BJDM"], ordinary);
        }

        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_REVIEW_DEPTH + 1),
            "]".repeat(MAX_REVIEW_DEPTH + 1)
        );
        let body = json!({"xkjgList":[{"XNXQDM":"20261","BJDM":deep}]});
        let admission = synthetic(&body.to_string(), "sid=abc_123");
        assert_eq!(admission.output["result"], "blocked");
        assert_eq!(admission.output["evidence"]["body_withheld"], true);
    }

    #[test]
    fn cookie_admission_cannot_hide_independent_session_rejection() {
        for body in [
            r#"{"msg":"请重新登录","xkjgList":[]}"#,
            r#"{"message":"session expired","xkjgList":"unreviewed shape"}"#,
        ] {
            let mut observed = observation(body.as_bytes());
            observed.issued_cookie = true;
            let admission = admit(observed, "20261", &CookieGuard("sid=synthetic"));
            assert_eq!(admission.output["result"], "blocked");
            assert!(admission.credential_rejected);
            assert!(!admission.challenge);
            assert!(!admission.network_failure);
            assert_eq!(admission.output["evidence"]["content_type"], Value::Null);
            assert_eq!(admission.output["evidence"]["body_withheld"], true);
            let admission = synthetic(body, "sid=synthetic");
            assert_eq!(admission.output["result"], "blocked");
            assert!(admission.credential_rejected);
        }
        let mut observed = observation(br#"{"msg":"ordinary","xkjgList":[]}"#);
        observed.issued_cookie = true;
        let admission = admit(observed, "20261", &CookieGuard("sid=synthetic"));
        assert_eq!(admission.output["result"], "blocked");
        assert!(!admission.credential_rejected);
    }

    #[test]
    fn redirects_challenges_cookie_issuance_and_authentication_never_become_lists() {
        let body = br#"{"xkjgList":[]}"#;
        let mut observed = observation(b"<p>redirect</p>");
        observed.status = 302;
        observed.content_type = Some("text/html");
        observed.redirect = true;
        let redirect = admit(observed, "20261", &CookieGuard("sid=synthetic"));
        assert_eq!(redirect.output["result"], "blocked");
        assert!(
            redirect.output["reason"]
                .as_str()
                .unwrap()
                .contains("no downgrade")
        );
        assert!(!redirect.credential_rejected);
        let mut observed = observation(body);
        observed.content_type = Some("application/json; session=new-secret");
        observed.issued_cookie = true;
        let issued = admit(observed, "20261", &CookieGuard("sid=synthetic"));
        assert_eq!(issued.output["result"], "blocked");
        assert_eq!(issued.output["evidence"]["content_type"], Value::Null);
        assert!(!issued.output.to_string().contains("new-secret"));
        for (status, header_challenge, rejected) in
            [(401, false, true), (403, false, true), (200, true, false)]
        {
            let mut observed = observation(body);
            observed.status = status;
            observed.header_challenge = header_challenge;
            let admission = admit(observed, "20261", &CookieGuard("sid=synthetic"));
            assert_eq!(admission.output["result"], "blocked");
            assert_eq!(admission.credential_rejected, rejected);
            assert!(admission.output["data"].is_null());
        }
        let mut observed = observation(body);
        observed.status = 429;
        observed.retry_present = true;
        let retry = admit(observed, "20261", &CookieGuard("sid=synthetic"));
        assert_eq!(retry.output["result"], "blocked");
        assert!(
            retry.output["reason"]
                .as_str()
                .unwrap()
                .contains("no retry")
        );
        let denied = synthetic(r#"{"msg":"请重新登录","xkjgList":[]}"#, "sid=synthetic");
        assert_eq!(denied.output["result"], "blocked");
        assert!(denied.credential_rejected);
        let unknown_message = synthetic(
            r#"{"msg":"unreviewed response","xkjgList":[]}"#,
            "sid=synthetic",
        );
        assert_eq!(unknown_message.output["result"], "parsed");
        assert_eq!(unknown_message.output["data"]["body_withheld"], true);
    }

    #[test]
    fn failed_body_retains_independent_header_safety_facts_for_settlement() {
        let mut observed = observation(br#"{"xkjgList":[]}"#);
        observed.status = 429;
        observed.retry_present = true;
        observed.header_challenge = true;
        observed.issued_cookie = true;
        observed.read_failed = true;
        let admission = admit(observed, "20261", &CookieGuard("sid=synthetic-cookie"));
        assert_eq!(admission.output["result"], "blocked");
        assert_eq!(admission.output["evidence"]["body_withheld"], true);
        assert_eq!(admission.output["evidence"]["content_type"], Value::Null);
        assert!(admission.challenge);
        assert!(admission.network_failure);
        assert!(!admission.credential_rejected);

        let mut observed = observation(br#"{"xkjgList":[]}"#);
        observed.declared_oversize = true;
        let admission = admit(observed, "20261", &CookieGuard("sid=synthetic-cookie"));
        assert!(admission.network_failure);
        assert_eq!(admission.output["result"], "blocked");
    }
}

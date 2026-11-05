//! Pending Boya HTTPS client. No UI automation or speculative write endpoints.
//!
//! List reads follow only what the source declares. `queryStudentSemesterCourseByPage`
//! is traversed page by page under one lease, bounded by the caller's `maxPages`
//! and by the source's own `totalPages`; `queryChosenCourse` declares no
//! pagination, so it is admitted once as a whole list. Neither path invents a
//! page count, and every early stop is reported as `complete:false` plus the
//! reason derived from the admitted pages.
use crate::recordings::session as cas;
use crate::{
    governor::{Governor, Outcome},
    net::{self, Error},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssl::{
    hash::{MessageDigest, hash},
    rand::rand_bytes,
    rsa::{Padding, Rsa},
    symm::{Cipher, decrypt, encrypt},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;
use zeroize::Zeroizing;
/// Admission ceiling for caller-declared page traversals, matching the other
/// bounded list reads. It bounds how many requests one invocation may make; it
/// is never used as a claim about how many pages the source has.
const MAX_TRAVERSAL_PAGES: u32 = 20;
fn default_max_pages() -> u32 {
    1
}
#[derive(Serialize)]
#[serde(transparent)]
struct PrivateValue(Value);
impl<'de> Deserialize<'de> for PrivateValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PrivateValue;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::from(value)))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(PrivateValue(Value::String(value)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = PrivateValue(Value::Array(Vec::new()));
                while let Some(mut value) = access.next_element::<PrivateValue>()? {
                    result
                        .0
                        .as_array_mut()
                        .unwrap()
                        .push(std::mem::take(&mut value.0));
                }
                Ok(result)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = PrivateValue(Value::Object(serde_json::Map::new()));
                while let Some(key) = access.next_key::<String>()? {
                    let mut key = Zeroizing::new(key);
                    let values = result.0.as_object_mut().unwrap();
                    if values.contains_key(key.as_str()) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let mut value = access.next_value::<PrivateValue>()?;
                    values.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
                }
                Ok(result)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
impl std::ops::Deref for PrivateValue {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl Drop for PrivateValue {
    fn drop(&mut self) {
        wipe_value(&mut self.0);
    }
}
fn wipe_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe_value),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                wipe_value(&mut value);
            }
        }
        _ => {}
    }
}
fn sensitive_value(value: &Value) -> bool {
    match value {
        Value::String(text) => sensitive_raw(text.as_bytes()),
        Value::Array(values) => values.iter().any(sensitive_value),
        Value::Object(values) => values.iter().any(|(key, value)| {
            // A literal null contains no issued token. Do not exempt non-null values
            // or other credential-shaped keys from the existing privacy check.
            !(key.eq_ignore_ascii_case("token") && value.is_null())
                && (sensitive_raw(key.as_bytes()) || sensitive_value(value))
        }),
        _ => false,
    }
}
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
fn optional_object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    struct Map<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Map<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, access: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(access))
        }
    }
    struct Optional<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Optional<T> {
        type Value = Option<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("object or null")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer
                .deserialize_map(Map(std::marker::PhantomData))
                .map(Some)
        }
    }
    deserializer.deserialize_option(Optional(std::marker::PhantomData))
}
const KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlHMQ3B5GsWnCe7Nlo1YiG/YmHdlOiKOST5aRm4iaqYSvhvWmwcigoyWTM+8bv2+sf6nQBRDWTY4KmNV7DBk1eDnTIQo6ENA31k5/tYCLEXgjPbEjCK9spiyB62fCT6cqOhbamJB0lcDJRO6Vo1m3dy+fD0jbxfDVBBNtyltIsDQIDAQAB";
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678";
fn err(code: &'static str, message: &'static str) -> Error {
    Error::new(code, message)
}
fn aes(input: &[u8], key: &[u8; 16], encrypting: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    if input.len() > 8 * 1024 * 1024 {
        return Err(err("body_limit", "encrypted body too large"));
    }
    let result = if encrypting {
        encrypt(Cipher::aes_128_ecb(), key, None, input)
    } else {
        decrypt(Cipher::aes_128_ecb(), key, None, input)
    };
    result
        .map(Zeroizing::new)
        .map_err(|_| err("crypto", "AES ciphertext or PKCS7 padding invalid"))
}
fn rsa(input: &[u8]) -> Result<String, Error> {
    // The supplied MIGf DER constant is SubjectPublicKeyInfo (PUBLIC KEY),
    // not the PKCS#1 RSAPublicKey (RSA PUBLIC KEY) encoding.
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{KEY}\n-----END PUBLIC KEY-----\n");
    let key = Rsa::public_key_from_pem(pem.as_bytes())
        .map_err(|_| err("crypto", "public key rejected"))?;
    let mut out = vec![0u8; key.size() as usize];
    let len = key
        .public_encrypt(input, &mut out, Padding::PKCS1)
        .map_err(|_| err("crypto", "RSA encryption failed"))?;
    out.truncate(len);
    Ok(STANDARD.encode(out))
}
fn random_key() -> Result<Zeroizing<[u8; 16]>, Error> {
    let mut key = Zeroizing::new([0u8; 16]);
    for byte in key.iter_mut() {
        loop {
            let mut r = [0u8; 1];
            rand_bytes(&mut r).map_err(|_| err("crypto", "secure randomness unavailable"))?;
            let ceiling = 256 - (256 % ALPHABET.len());
            if (r[0] as usize) < ceiling {
                *byte = ALPHABET[r[0] as usize % ALPHABET.len()];
                break;
            }
        }
    }
    Ok(key)
}
fn sensitive_raw(bytes: &[u8]) -> bool {
    if bytes
        .windows(2)
        .any(|part| part == b"\\u" || part == b"\\x")
        || bytes.windows(2).any(|part| part == b"&#")
    {
        return true;
    }
    fn marked(bytes: &[u8]) -> bool {
        [
            b"token".as_slice(),
            b"cookie",
            b"password",
            b"ticket",
            b"authorization",
            b"session",
            b"csrf",
            b"secret",
            b"loginname",
            b"login_name",
            b"credential",
            b"bearer",
            b"execution",
            b"nonce",
            b"jwt",
        ]
        .iter()
        .any(|marker| {
            bytes
                .windows(marker.len())
                .any(|part| part.eq_ignore_ascii_case(marker))
        })
    }
    marked(bytes)
        || url::form_urlencoded::parse(bytes).any(|(key, value)| {
            let key = Zeroizing::new(key.into_owned());
            let value = Zeroizing::new(value.into_owned());
            marked(key.as_bytes()) || marked(value.as_bytes())
        })
}
fn safe_mime(value: Option<&str>) -> Option<&'static str> {
    let essence = value?.split(';').next()?.trim();
    [
        "application/json",
        "text/plain",
        "text/html",
        "application/xhtml+xml",
        "application/octet-stream",
    ]
    .into_iter()
    .find(|candidate| essence.eq_ignore_ascii_case(candidate))
}
fn response_content_type(headers: &reqwest::header::HeaderMap) -> Zeroizing<Option<String>> {
    Zeroizing::new(if headers.get_all("content-type").iter().count() == 1 {
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    } else {
        None
    })
}
fn evidence(bytes: &[u8], content_type: Option<&str>, withheld_reason: Option<&str>) -> Value {
    let content_type = safe_mime(content_type);
    json!({"encoding":"base64","content_type":content_type,"byte_length":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),"data":withheld_reason.is_none().then(||STANDARD.encode(bytes)),"raw_withheld":withheld_reason.is_some(),"raw_withheld_reason":withheld_reason})
}
fn raw_evidence(bytes: &[u8], content_type: Option<&str>, complete: bool) -> Value {
    let withheld = match crate::html::assess_challenge_body(bytes, content_type, complete) {
        crate::html::ChallengeAssessment::Clear => None,
        crate::html::ChallengeAssessment::Detected => Some("challenge_detected"),
        crate::html::ChallengeAssessment::Unreviewed => Some("response_safety_unreviewed"),
    };
    evidence(
        bytes,
        content_type,
        if sensitive_raw(bytes)
            || serde_json::from_slice::<PrivateValue>(bytes)
                .ok()
                .is_some_and(|value| sensitive_value(&value))
        {
            Some("sensitive_response_material")
        } else {
            withheld
        },
    )
}
fn fallback(bytes: &[u8], content_type: Option<&str>, reason: &str) -> Value {
    json!({"result":"fallback","fallback_reason":reason,"raw_evidence":raw_evidence(bytes,content_type,true)})
}
fn withheld_fallback(bytes: &[u8], content_type: Option<&str>) -> Value {
    json!({"result":"fallback","fallback_reason":"sensitive_response_withheld","raw_evidence":evidence(bytes,content_type,Some("credential_echo"))})
}

fn unreviewed_fallback(bytes: &[u8], content_type: Option<&str>) -> Value {
    json!({"result":"fallback","fallback_reason":"response_safety_unreviewed","raw_evidence":evidence(bytes,content_type,Some("response_safety_unreviewed"))})
}

/// The outcome of screening untrusted response material against every
/// secret the invocation holds. `Echo` is a definite credential match.
/// `Unreviewable` means part of the material could not be screened — an
/// escaped JSON literal a strict decoder rejects — so neither a definite
/// echo nor safety was established. `Clear` means every check ran to
/// completion without a match.
#[derive(Clone, Copy)]
enum ResponseScreening {
    Clear,
    Echo,
    Unreviewable,
}

fn response_screening(
    bytes: &[u8],
    content_type: Option<&str>,
    contains_secret: impl Fn(&[u8]) -> bool,
) -> ResponseScreening {
    if contains_secret(bytes) || content_type.is_some_and(|value| contains_secret(value.as_bytes()))
    {
        ResponseScreening::Echo
    } else {
        match serde_json::from_slice::<PrivateValue>(bytes) {
            // Strict typed admission succeeded: `value_carries_secret` has
            // already screened every decoded string, key and scalar, which
            // is exactly the decoded view the lexical scan would rebuild.
            // No literal is decoded a second time.
            Ok(value) => {
                if value_carries_secret(&value, &contains_secret) {
                    ResponseScreening::Echo
                } else {
                    ResponseScreening::Clear
                }
            }
            // Strict admission failed (a duplicate key, a positional root,
            // truncated structure): only the lexical fallback can still
            // review the decoded spellings.
            Err(_) => escaped_string_screening(bytes, &contains_secret),
        }
    }
}

/// Screen JSON string spellings that only exist after decoding. A body that
/// fails strict `PrivateValue` parsing (a duplicate key, a positional root,
/// truncated structure) can still encode a retained credential inside an
/// escaped string (`\u0061`, `\/`, `\\`), and the raw bytes never contain
/// the decoded spelling. Only literals that carry a JSON escape need
/// decoding; every unescaped spelling is already covered by the byte-level
/// check. An escaped literal that cannot be decoded — a string cut off
/// before its closing quote or an invalid escape — cannot be screened at
/// all: a lenient consumer may still recover a credential spelling from
/// it, so it is unreviewable rather than presumed safe or presumed an
/// echo.
fn escaped_string_screening(
    bytes: &[u8],
    contains_secret: &dyn Fn(&[u8]) -> bool,
) -> ResponseScreening {
    let mut cursor = 0;
    let mut unreviewable = false;
    while cursor < bytes.len() {
        if bytes[cursor] != b'"' {
            cursor += 1;
            continue;
        }
        let opening = cursor;
        cursor += 1;
        let mut escaped = false;
        let mut terminated = false;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => {
                    escaped = true;
                    cursor = cursor.saturating_add(2);
                }
                b'"' => {
                    terminated = true;
                    break;
                }
                _ => cursor += 1,
            }
        }
        if !terminated {
            // A cut-off literal carrying an escape is never presumed safe:
            // a lenient consumer may recover the credential spelling a
            // strict decoder rejects.
            unreviewable |= escaped;
            break;
        }
        if escaped {
            match serde_json::from_slice::<String>(&bytes[opening..=cursor]) {
                Ok(value) => {
                    let value = Zeroizing::new(value);
                    if contains_secret(value.as_bytes()) {
                        return ResponseScreening::Echo;
                    }
                }
                // An escaped literal that cannot be decoded cannot be
                // screened; record it and keep looking for a definite
                // echo, which outranks the unreviewable verdict.
                Err(_) => unreviewable = true,
            }
        }
        cursor += 1;
    }
    if unreviewable {
        ResponseScreening::Unreviewable
    } else {
        ResponseScreening::Clear
    }
}

#[cfg(test)]
fn response_contains_secret(bytes: &[u8], content_type: Option<&str>, secret: &str) -> bool {
    matches!(
        response_screening(bytes, content_type, |candidate| {
            crate::net::carries_secret(candidate, secret)
        }),
        ResponseScreening::Echo
    )
}
fn value_carries_secret(value: &Value, contains_secret: &dyn Fn(&[u8]) -> bool) -> bool {
    match value {
        Value::String(text) => contains_secret(text.as_bytes()),
        Value::Array(values) => values
            .iter()
            .any(|value| value_carries_secret(value, contains_secret)),
        Value::Object(values) => values.iter().any(|(key, value)| {
            contains_secret(key.as_bytes()) || value_carries_secret(value, contains_secret)
        }),
        Value::Number(_) | Value::Bool(_) | Value::Null => {
            crate::net::json_scalar_matches(value, contains_secret)
        }
    }
}
#[cfg(test)]
fn value_contains_secret(value: &Value, secret: &str) -> bool {
    !secret.is_empty()
        && value_carries_secret(value, &|candidate| {
            crate::net::carries_secret(candidate, secret)
        })
}
#[derive(Clone, Copy, Default)]
struct SourceFields {
    data: bool,
    status: bool,
    errmsg: bool,
}
fn projected_source_carries_secret(
    value: &Value,
    fields: SourceFields,
    contains_secret: &dyn Fn(&[u8]) -> bool,
) -> bool {
    match value.get("result").and_then(Value::as_str) {
        Some("success") => {
            fields.data
                && value
                    .get("data")
                    .is_some_and(|value| value_carries_secret(value, contains_secret))
        }
        Some("upstream_error") => [
            ("status", fields.status),
            ("data", fields.data),
            ("errmsg", fields.errmsg),
        ]
        .iter()
        .any(|(key, present)| {
            *present
                && value
                    .get(*key)
                    .is_some_and(|value| value_carries_secret(value, contains_secret))
        }),
        // Fallback metadata is generated locally; the original wire bytes and
        // content type were independently checked before constructing it.
        _ => false,
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "api", content = "payload", deny_unknown_fields)]
pub enum ReadRequest {
    #[serde(rename = "getUserProfile")]
    Profile,
    #[serde(rename = "queryStudentSemesterCourseByPage")]
    Courses(PageRequest),
    #[serde(rename = "queryCourseById")]
    Course(IdRequest),
    #[serde(rename = "queryChosenCourse")]
    Chosen(DateRequest),
    #[serde(rename = "querySelectableCourse")]
    Selectable,
    #[serde(rename = "queryForeCourse")]
    Fore,
    #[serde(rename = "getAllConfig")]
    Config,
    #[serde(rename = "queryStatisticByUserId")]
    Statistics,
}
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageRequest {
    pub page_number: u32,
    pub page_size: u32,
    /// Caller-declared traversal bound. It is admitted locally and never sent
    /// upstream, so the encrypted page payload stays `pageNumber`/`pageSize`.
    #[serde(skip_serializing)]
    pub max_pages: u32,
}
impl<'de> Deserialize<'de> for PageRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            #[serde(rename = "pageNumber")]
            page_number: u32,
            #[serde(rename = "pageSize")]
            page_size: u32,
            #[serde(rename = "maxPages", default = "default_max_pages")]
            max_pages: u32,
        }
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PageRequest;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("query object")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                _: A,
            ) -> Result<Self::Value, A::Error> {
                Err(serde::de::Error::custom("positional query refused"))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                access: A,
            ) -> Result<Self::Value, A::Error> {
                Strict::deserialize(serde::de::value::MapAccessDeserializer::new(access)).map(
                    |value| PageRequest {
                        page_number: value.page_number,
                        page_size: value.page_size,
                        max_pages: value.max_pages,
                    },
                )
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdRequest {
    pub id: String,
}
impl<'de> Deserialize<'de> for IdRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            id: String,
        }
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = IdRequest;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("query object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                access: A,
            ) -> Result<Self::Value, A::Error> {
                Fields::deserialize(serde::de::value::MapAccessDeserializer::new(access))
                    .map(|fields| IdRequest { id: fields.id })
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DateRequest {
    pub start_date: String,
    pub end_date: String,
}
impl<'de> Deserialize<'de> for DateRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            #[serde(rename = "startDate")]
            start_date: String,
            #[serde(rename = "endDate")]
            end_date: String,
        }
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = DateRequest;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("query object")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                _: A,
            ) -> Result<Self::Value, A::Error> {
                Err(serde::de::Error::custom("positional query refused"))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                access: A,
            ) -> Result<Self::Value, A::Error> {
                Strict::deserialize(serde::de::value::MapAccessDeserializer::new(access)).map(
                    |value| DateRequest {
                        start_date: value.start_date,
                        end_date: value.end_date,
                    },
                )
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
fn payload(req: &ReadRequest) -> Result<(&'static str, Value), Error> {
    Ok(match req {
        ReadRequest::Profile => ("getUserProfile", json!({})),
        ReadRequest::Courses(p) => {
            if p.page_size == 0 || p.page_size > 200 {
                return Err(err("invalid_input", "pageSize must be 1..200"));
            }
            if p.max_pages == 0 || p.max_pages > MAX_TRAVERSAL_PAGES {
                return Err(err("invalid_input", "maxPages must be 1..20"));
            }
            ("queryStudentSemesterCourseByPage", json!(p))
        }
        ReadRequest::Course(p) => ("queryCourseById", json!(p)),
        ReadRequest::Chosen(p) => ("queryChosenCourse", json!(p)),
        ReadRequest::Selectable => ("querySelectableCourse", json!({})),
        ReadRequest::Fore => ("queryForeCourse", json!({})),
        ReadRequest::Config => ("getAllConfig", json!({})),
        ReadRequest::Statistics => ("queryStatisticByUserId", json!({})),
    })
}
fn decode_response_with_fields(
    bytes: &[u8],
    content_type: Option<&str>,
    key: &[u8; 16],
) -> (Value, SourceFields) {
    if crate::html::assess_challenge_body(bytes, content_type, true)
        != crate::html::ChallengeAssessment::Clear
    {
        return (
            fallback(bytes, content_type, "response_safety_not_clear"),
            SourceFields::default(),
        );
    }
    // The reference client accepts a JSON string or raw base64. Keep the
    // original bytes for evidence; only the ciphertext spelling is unwrapped.
    let quoted = if bytes.trim_ascii_start().first() == Some(&b'"') {
        serde_json::from_slice::<String>(bytes)
            .ok()
            .map(Zeroizing::new)
    } else {
        None
    };
    let ciphertext = quoted.as_ref().map_or(bytes, |text| text.as_bytes());
    let decoded = STANDARD
        .decode(ciphertext)
        .ok()
        .map(Zeroizing::new)
        .and_then(|b| aes(&b, key, false).ok())
        .and_then(|b| serde_json::from_slice::<PrivateValue>(&b).ok());
    if decoded.as_ref().is_some_and(|value| sensitive_value(value)) {
        return (
            withheld_fallback(bytes, content_type),
            SourceFields::default(),
        );
    }
    match decoded {
        Some(v) if v.get("status").and_then(Value::as_str) == Some("0") => {
            let fields = SourceFields {
                data: v.get("data").is_some(),
                ..SourceFields::default()
            };
            (
                json!({"result":"success","data":v.get("data").cloned().unwrap_or(Value::Null)}),
                fields,
            )
        }
        Some(v) if v.get("status").and_then(Value::as_str).is_some() => {
            let fields = SourceFields {
                status: true,
                data: v.get("data").is_some(),
                errmsg: v.get("errmsg").is_some(),
            };
            (
                json!({"result":"upstream_error","status":v["status"],"data":v.get("data"),"errmsg":v.get("errmsg")}),
                fields,
            )
        }
        _ => (
            fallback(bytes, content_type, "base64_aes_json_contract_unrecognized"),
            SourceFields::default(),
        ),
    }
}
pub fn decode_response(bytes: &[u8], content_type: Option<&str>, key: &[u8; 16]) -> Value {
    decode_response_with_fields(bytes, content_type, key).0
}
pub fn parse_page(data: &Value) -> Result<Value, Error> {
    let content = data
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| err("invalid_page", "content is not a list"))?;
    let fields = ["totalElements", "totalPages", "size", "number"];
    if fields
        .iter()
        .any(|k| data.get(k).and_then(Value::as_u64).is_none())
        || data["size"].as_u64() == Some(0)
        || content.len() as u64 > data["size"].as_u64().unwrap_or(0)
    {
        return Err(err("invalid_page", "pagination metadata invalid"));
    }
    Ok(data.clone())
}

enum Step {
    Continue,
    Done,
}

/// One bounded traversal of the source-declared course pages.
///
/// Every stop decision uses facts the admitted pages declared: the echoed page
/// number, `totalElements`, `totalPages` and the declared `size`. `max_pages`
/// bounds how many requests one invocation may make; it is never used as a
/// claim about the page count. A page whose declarations cannot be reconciled
/// stops the traversal instead of being completed or extended by a guess.
struct CourseTraversal {
    start: u32,
    page_size: u32,
    max_pages: u32,
    next_page: u32,
    total_elements: Option<u64>,
    total_pages: Option<u64>,
    size: Option<u64>,
    offset: Option<i128>,
    seen: BTreeSet<u64>,
    entries: Vec<Value>,
    pages: Vec<Value>,
    failure: Option<Value>,
    result: &'static str,
    complete: bool,
    reason: Option<&'static str>,
}

impl CourseTraversal {
    fn new(page: &PageRequest) -> Self {
        Self {
            start: page.page_number,
            page_size: page.page_size,
            max_pages: page.max_pages,
            next_page: page.page_number,
            total_elements: None,
            total_pages: None,
            size: None,
            offset: None,
            seen: BTreeSet::new(),
            entries: Vec::new(),
            pages: Vec::new(),
            failure: None,
            result: "partial",
            complete: false,
            reason: None,
        }
    }

    /// Stop without admitting another page. Admitted records stay published.
    fn halt(&mut self, reason: &'static str) {
        self.complete = false;
        self.reason = Some(reason);
    }

    fn halt_page(&mut self, reason: &'static str, value: &Value) {
        self.failure = Some(value.clone());
        self.halt(reason);
    }

    /// Admit one already-decrypted page value. `Done` means no further request
    /// may be sent for this traversal.
    fn advance(&mut self, value: &Value) -> Step {
        if value.get("result").and_then(Value::as_str) != Some("success") {
            self.result = match value.get("result").and_then(Value::as_str) {
                Some("fallback") => "fallback",
                Some("upstream_error") => "upstream_error",
                _ => "partial",
            };
            self.failure = Some(value.clone());
            self.halt("source_page_not_success");
            return Step::Done;
        }
        let data = &value["data"];
        if parse_page(data).is_err() {
            self.halt_page("invalid_pagination_contract", value);
            return Step::Done;
        }
        let number = data["number"].as_u64().unwrap_or_default();
        let total_elements = data["totalElements"].as_u64().unwrap_or_default();
        let total_pages = data["totalPages"].as_u64().unwrap_or_default();
        let size = data["size"].as_u64().unwrap_or_default();
        let content = data["content"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        // The request-to-echo page mapping is learned from the first admitted
        // page and must hold for every later page, so a source whose page
        // numbering starts elsewhere is followed rather than assumed. A page
        // that does not answer the requested position is refused.
        let offset = match self.offset {
            Some(offset) => offset,
            None => {
                let offset = i128::from(self.next_page) - i128::from(number);
                self.offset = Some(offset);
                offset
            }
        };
        if i128::from(number) + offset != i128::from(self.next_page) {
            self.halt_page("pagination_page_mismatch", value);
            return Step::Done;
        }
        match (self.total_elements, self.total_pages, self.size) {
            (None, None, None) => {
                self.total_elements = Some(total_elements);
                self.total_pages = Some(total_pages);
                self.size = Some(size);
            }
            (Some(elements), Some(pages), Some(declared))
                if elements == total_elements && pages == total_pages && declared == size => {}
            _ => {
                self.halt_page("pagination_changed", value);
                return Step::Done;
            }
        }
        // Every page before the declared last one must be a full page. A
        // short intermediate page means the declared totals no longer describe
        // the served content; no item position is assumed.
        let last_declared = number.saturating_add(1) >= total_pages;
        if !last_declared && !content.is_empty() && content.len() as u64 != size {
            self.halt_page("pagination_inconsistent", value);
            return Step::Done;
        }
        for entry in content {
            let Some(id) = entry.get("id").and_then(Value::as_u64) else {
                self.halt_page("entry_id_unconfirmed", value);
                return Step::Done;
            };
            if !self.seen.insert(id) {
                self.halt_page("duplicate_course_id", value);
                return Step::Done;
            }
            self.entries.push(entry.clone());
        }
        self.pages.push(json!({"number":number,"count":content.len(),"size":size,"total_elements":total_elements,"total_pages":total_pages}));
        let next = i128::from(number) + 1 + offset;
        self.next_page = u32::try_from(next).unwrap_or(u32::MAX);
        let collected = self.entries.len() as u64;
        let extent_consistent = if total_elements == 0 {
            total_pages <= 1 && number == 0 && content.is_empty()
        } else {
            total_pages == total_elements.div_ceil(size) && number < total_pages
        };
        if collected > total_elements || !extent_consistent {
            self.halt_page("pagination_inconsistent", value);
            return Step::Done;
        }
        if collected == total_elements && last_declared {
            self.complete = true;
            self.reason = None;
            return Step::Done;
        }
        if content.is_empty() {
            self.halt_page("empty_page", value);
            return Step::Done;
        }
        if last_declared {
            self.halt_page("declared_pages_exhausted", value);
            return Step::Done;
        }
        if self.pages.len() as u32 >= self.max_pages {
            self.halt("page_bound_reached");
            return Step::Done;
        }
        Step::Continue
    }

    fn envelope(self) -> Value {
        let CourseTraversal {
            start,
            page_size,
            max_pages,
            next_page: _,
            total_elements,
            total_pages,
            size,
            offset: _,
            seen: _,
            entries,
            pages,
            failure,
            result,
            complete,
            reason,
        } = self;
        let entry_count = entries.len();
        json!({"result":if complete{"success"}else{result},"source":"queryStudentSemesterCourseByPage","list_contract":"page",
            "complete":complete,"incomplete_reason":reason,"entries":entries,"entry_count":entry_count,
            "pagination":{"start_page":start,"requested_page_size":page_size,"max_pages":max_pages,
                "pages_fetched":pages.len(),"declared_page_size":size,
                "declared_total_elements":total_elements,"declared_total_pages":total_pages,"pages":pages},
            "page_failure":failure})
    }
}

/// `queryChosenCourse` declares no pagination: the source returns the complete
/// `courseList` for the requested window in one response. Completeness is
/// reported from that declared contract, never from an inferred page count.
fn whole_list(value: Value) -> Value {
    if value.get("result").and_then(Value::as_str) != Some("success") {
        let mut value = value;
        if let Some(map) = value.as_object_mut() {
            map.insert("complete".into(), json!(false));
            map.insert("incomplete_reason".into(), json!("source_page_not_success"));
        }
        return value;
    }
    let declared = value
        .get("data")
        .and_then(|data| data.get("courseList"))
        .and_then(Value::as_array)
        .cloned();
    let Some(declared) = declared else {
        return json!({"result":"partial","source":"queryChosenCourse","list_contract":"whole_list","complete":false,
            "incomplete_reason":"list_contract_unrecognized","entries":Value::Null,"entry_count":Value::Null,
            "pagination":Value::Null,"page_failure":Value::Null,"data":value.get("data").cloned().unwrap_or(Value::Null)});
    };
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    let mut reason = None;
    for entry in declared {
        let Some(id) = entry.get("id").and_then(Value::as_u64) else {
            reason = Some("entry_id_unconfirmed");
            break;
        };
        if !seen.insert(id) {
            reason = Some("duplicate_course_id");
            break;
        }
        entries.push(entry);
    }
    let entry_count = entries.len();
    let complete = reason.is_none();
    json!({"result":if complete{"success"}else{"partial"},"source":"queryChosenCourse","list_contract":"whole_list",
        "complete":complete,"incomplete_reason":reason,"entries":entries,"entry_count":entry_count,
        "pagination":Value::Null,"page_failure":if complete {Value::Null} else {value}})
}
pub struct BoyaClient {
    http: reqwest::blocking::Client,
    governor: Governor,
}
struct ReadResponse<'a> {
    bytes: &'a [u8],
    ct: Option<&'a str>,
    status: u16,
    challenge: bool,
    body_failed: bool,
    assessment: crate::html::ChallengeAssessment,
}

/// The credential values issued by `Set-Cookie` headers during one complete
/// read invocation. This client maintains no cookie jar: an issued value is
/// never persisted, adopted or transmitted, but an echo of it inside any
/// response of the same invocation — including the response that issued it
/// and any later page — is still a credential disclosure. The guard is
/// created once per invocation and accumulates every fresh response's
/// values without resetting or evicting between pages; it is zeroized with
/// the invocation.
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
    err(
        "invalid_headers",
        "the Boya response issued a cookie that cannot be reviewed",
    )
}

impl IssuedCookies {
    /// Review one response's `Set-Cookie` values while the raw header map is
    /// still available and retain them for the rest of the invocation. Only
    /// the first `name=value` pair is credential material; attributes are
    /// not screened. A header that cannot be parsed on its own terms (a
    /// missing name, a missing `=`, a control byte, or ambiguous quoting)
    /// refuses the response. An empty value is a deletion, not a
    /// transmitting secret, so it is not retained.
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
            // The same cookie grammar as the authentication jar: invalid
            // names or folded first pairs cannot establish which value must
            // remain private, so they refuse instead of guessing.
            if !cas::valid_cookie_name(name) || !cas::valid_cookie_value(value) {
                return Err(issued_cookie_refusal());
            }
            let unquoted = value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .unwrap_or(value);
            if unquoted.is_empty() {
                // `name=` or `name=""`: upstream is deleting this cookie, so
                // there is no transmitting secret to screen.
                continue;
            }
            // An identical declaration carries no new secret, so a repeated
            // `Set-Cookie` on later pages must not grow or exhaust the
            // history. Compare before the bounds so an already-retained
            // value is never refused by a full guard.
            if self
                .values
                .iter()
                .any(|retained| retained.as_str() == value)
            {
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

/// Every secret one read invocation may have handled: the issued auth
/// token, every credential the authentication attempt retained — the
/// complete transmitted Cookie headers and the cookie values of every
/// scope, including path-excluded, replaced, expired or dropped values —
/// and every cookie value a read response issued. The guard is
/// invocation-only: nothing in it is persisted or transmitted.
struct ScreenedSecrets<'a> {
    token: &'a str,
    session: Option<&'a cas::ServiceSession>,
    /// The submitted password is not part of the session jar's retained
    /// history, but a response that echoes it is still a credential
    /// disclosure. The username is not screened: a decoded profile
    /// legitimately reports it, matching the smart reader's choice.
    password: Option<&'a str>,
    issued: IssuedCookies,
}

impl ScreenedSecrets<'_> {
    fn carries(&self, bytes: &[u8]) -> bool {
        net::carries_secret(bytes, self.token)
            || self
                .session
                .is_some_and(|session| session.contains_secret_bytes(bytes))
            || self
                .password
                .is_some_and(|password| net::carries_secret(bytes, password))
            || self.issued.carries(bytes)
    }
}

/// One response admitted under a lease that stays pending until the whole
/// traversal is settled with the last exchange's facts.
struct Exchange {
    value: Result<Value, Error>,
    status: u16,
    retry_after: Option<String>,
    challenge: bool,
    body_failed: bool,
}
enum ExchangeError {
    Transport(Error),
    Governor(Error),
}
/// Settle the pending lease with the last observed exchange. Observations were
/// already persisted by `observe_http_many`; this only releases exclusivity.
fn settle(
    lease: crate::governor::RequestLease<'_>,
    status: u16,
    retry_after: Option<&str>,
    challenge: bool,
    body_failed: bool,
) -> Result<(), Error> {
    lease
        .finish(Outcome::Http {
            status,
            retry_after,
            challenge,
            network_failure: body_failed,
        })
        .map_err(|_| err("governor_denied", "settlement failed"))
}
/// Extract only from the canonical HTTPS application URL, never from a CAS
/// ticket or an untrusted redirect host. Returned token is secret.
pub fn auth_token(final_url: &str) -> Result<Zeroizing<String>, Error> {
    let tail = final_url
        .strip_prefix("https://bykc.buaa.edu.cn/")
        .ok_or_else(|| err("login_contract", "token URL must be canonical HTTPS Boya"))?;
    if tail.contains('#') || tail.chars().any(char::is_control) {
        return Err(err("login_contract", "invalid final URL"));
    }
    let query = tail
        .split_once('?')
        .map(|(_, query)| query)
        .ok_or_else(|| err("login_required", "authenticated final URL has no token"))?;
    let mut token = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let key = Zeroizing::new(key.into_owned());
        let value = Zeroizing::new(value.into_owned());
        if key.as_str() == "token" {
            if token.is_some() {
                return Err(err("login_contract", "ambiguous auth token"));
            }
            token = Some(value);
        }
    }
    token
        .filter(|value| !value.is_empty())
        .ok_or_else(|| err("login_required", "authenticated final URL has no token"))
}
impl BoyaClient {
    pub fn open() -> Result<Self, Error> {
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|_| err("transport", "HTTPS initialization failed"))?,
            governor: Governor::open()
                .map_err(|_| err("governor_denied", "shared governor unavailable"))?,
        })
    }
    /// Token-issuing CAS authentication remains closed before transport. The
    /// current outcome contract cannot simultaneously represent indeterminate
    /// authentication on an HTTP success status and preserve body failures;
    /// sending would also require a one-shot Authentication lease.
    pub fn login(&self, _cookie: &str, _legacy_path: bool) -> Result<Zeroizing<String>, Error> {
        Err(err(
            "unsupported",
            "Boya CAS token issuance is blocked: one-shot authentication outcome settlement cannot be proved",
        ))
    }
    /// Token must come from a governed authenticated CAS session, never argv.
    pub fn read(&self, auth_token: &str, req: &ReadRequest) -> Result<Value, Error> {
        let (request, key) = Self::prepare(&self.http, auth_token, req)?;
        let lease = net::acquire(&self.governor)?;
        Self::execute(
            &self.http,
            lease,
            request,
            key,
            ScreenedSecrets {
                token: auth_token,
                session: None,
                password: None,
                issued: IssuedCookies::default(),
            },
            req,
        )
    }

    /// Build the encrypted read request without touching the shared governor.
    pub(crate) fn prepare(
        client: &reqwest::blocking::Client,
        auth_token: &str,
        req: &ReadRequest,
    ) -> Result<(reqwest::blocking::Request, Zeroizing<[u8; 16]>), Error> {
        if auth_token.is_empty() || reqwest::header::HeaderValue::from_str(auth_token).is_err() {
            return Err(err(
                "invalid_input",
                "credential header cannot be constructed",
            ));
        }
        let (api, data) = payload(req)?;
        let key = random_key()?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&data).map_err(|_| err("json", "payload serialization failed"))?,
        );
        let body = STANDARD.encode(aes(&plain, &key, true)?.as_slice());
        let digest = hash(MessageDigest::sha1(), plain.as_slice())
            .map_err(|_| err("crypto", "SHA1 digest failed"))?;
        let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let ak = rsa(key.as_slice())?;
        let sk = rsa(digest_hex.as_bytes())?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| err("clock", "invalid clock"))?
            .as_millis()
            .to_string();
        let request = client
            .post(format!("https://bykc.buaa.edu.cn/sscv/{api}"))
            .header("auth_token", auth_token)
            .header("authtoken", auth_token)
            .header("Referer", "https://bykc.buaa.edu.cn/system/course-select")
            .header("Origin", "https://bykc.buaa.edu.cn")
            .header("Content-Type", "application/json;charset=UTF-8")
            .header("ak", ak)
            .header("sk", sk)
            .header("ts", ts)
            .body(body)
            .timeout(std::time::Duration::from_secs(30));
        Ok((
            request
                .build()
                .map_err(|_| err("transport", "cannot build the read request"))?,
            key,
        ))
    }

    /// Transmit one prepared read under an already-reserved lease. The lease
    /// stays pending so a declared next page can be requested in the same
    /// attempt; the caller settles it after the last page.
    fn exchange(
        client: &reqwest::blocking::Client,
        lease: &mut crate::governor::RequestLease<'_>,
        request: reqwest::blocking::Request,
        key: Zeroizing<[u8; 16]>,
        secrets: &mut ScreenedSecrets<'_>,
        req: &ReadRequest,
    ) -> Result<Exchange, ExchangeError> {
        let mut response = match lease.start_request(|| client.execute(request)) {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                return Err(ExchangeError::Transport(err(
                    "network_error",
                    "HTTPS request failed; not retried",
                )));
            }
            Err(crate::governor::FollowupError::Governor(_)) => {
                return Err(ExchangeError::Governor(err(
                    "governor_denied",
                    "request-start admission unavailable",
                )));
            }
        };
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let header_challenge = response
            .headers()
            .iter()
            .any(|(k, v)| net::challenge_header(k.as_str(), v.as_bytes()));
        let ct = response_content_type(response.headers());
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
            .map_err(|_| {
                ExchangeError::Governor(err("governor_denied", "cannot persist response headers"))
            })?;
        // Every `Set-Cookie` value must be reviewed while the raw header map
        // is still available and retained for the rest of the invocation.
        // Issuance itself is not a refusal: the values join the screening
        // guard only, never a jar, a request or any store. A declaration
        // that cannot be reviewed refuses the whole response rather than
        // screening a subset.
        let issued_failure = secrets.issued.absorb(response.headers()).err();
        let mut bytes = Zeroizing::new(Vec::new());
        let failure = response
            .by_ref()
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .is_err();
        let body_failed = failure || bytes.len() > 8 * 1024 * 1024;
        let assessment = crate::html::assess_challenge_body(&bytes, ct.as_deref(), !body_failed);
        let challenge =
            header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
        drop(response);
        let value = match issued_failure {
            Some(error) => Err(error),
            None => admit_response(
                ReadResponse {
                    bytes: &bytes,
                    ct: ct.as_deref(),
                    status,
                    challenge,
                    body_failed,
                    assessment,
                },
                &|candidate| secrets.carries(candidate),
                &key,
                req,
            ),
        };
        Ok(Exchange {
            value,
            status,
            retry_after: retry,
            challenge,
            body_failed,
        })
    }

    /// Transmit one prepared read under an already-reserved lease and settle it.
    /// `semester_courses` may continue with the next source-declared page while
    /// the caller's bound allows it; every other operation is one exchange.
    fn execute(
        client: &reqwest::blocking::Client,
        mut lease: crate::governor::RequestLease<'_>,
        request: reqwest::blocking::Request,
        key: Zeroizing<[u8; 16]>,
        mut secrets: ScreenedSecrets<'_>,
        req: &ReadRequest,
    ) -> Result<Value, Error> {
        let first = match Self::exchange(client, &mut lease, request, key, &mut secrets, req) {
            Ok(exchange) => exchange,
            Err(ExchangeError::Transport(error)) => {
                lease
                    .finish(Outcome::NetworkFailure)
                    .map_err(|_| err("governor_denied", "settlement failed"))?;
                return Err(error);
            }
            Err(ExchangeError::Governor(error)) => return Err(error),
        };
        let Exchange {
            value,
            status,
            retry_after,
            challenge,
            body_failed,
        } = first;
        let page = match req {
            ReadRequest::Courses(page) => page,
            _ => {
                let value = match value {
                    Ok(value) => {
                        if matches!(req, ReadRequest::Chosen(_)) {
                            whole_list(value)
                        } else {
                            value
                        }
                    }
                    Err(error) => {
                        settle(
                            lease,
                            status,
                            retry_after.as_deref(),
                            challenge,
                            body_failed,
                        )?;
                        return Err(error);
                    }
                };
                settle(
                    lease,
                    status,
                    retry_after.as_deref(),
                    challenge,
                    body_failed,
                )?;
                return Ok(value);
            }
        };
        let mut value = match value {
            Ok(value) => value,
            Err(error) => {
                settle(
                    lease,
                    status,
                    retry_after.as_deref(),
                    challenge,
                    body_failed,
                )?;
                return Err(error);
            }
        };
        let mut traversal = CourseTraversal::new(page);
        let mut last = (status, retry_after, challenge, body_failed);
        let mut network_failure = false;
        loop {
            if matches!(traversal.advance(&value), Step::Done) {
                break;
            }
            // Only a declared next page is requested, and only after the prior
            // body is fully consumed. A cooldown stops the traversal: no page
            // is retried, skipped or renumbered.
            let reservation = lease
                .reserve_followup()
                .map_err(|_| err("governor_denied", "cannot admit the Boya page follow-up"))?;
            if !reservation.cooldown_wait.is_zero() {
                traversal.halt("governor_cooldown");
                break;
            }
            if !reservation.request_wait.is_zero() {
                std::thread::sleep(reservation.request_wait);
            }
            let next = ReadRequest::Courses(PageRequest {
                page_number: traversal.next_page,
                page_size: page.page_size,
                max_pages: page.max_pages,
            });
            let (request, key) = match Self::prepare(client, secrets.token, &next) {
                Ok(prepared) => prepared,
                Err(error) => {
                    traversal.halt(error.code);
                    break;
                }
            };
            let exchange =
                match Self::exchange(client, &mut lease, request, key, &mut secrets, &next) {
                    Ok(exchange) => exchange,
                    Err(ExchangeError::Transport(error)) => {
                        traversal.halt(error.code);
                        network_failure = true;
                        break;
                    }
                    Err(ExchangeError::Governor(error)) => return Err(error),
                };
            let Exchange {
                value: next_value,
                status,
                retry_after,
                challenge,
                body_failed,
            } = exchange;
            match next_value {
                Ok(next_value) => value = next_value,
                Err(error) => {
                    // Keep previously admitted records; the rejected body's
                    // bytes stay withheld and only its typed failure is used
                    // by the same terminal collector path as other failures.
                    value =
                        json!({"result":"page_rejected","error":error.code,"http_status":status});
                }
            }
            last = (status, retry_after, challenge, body_failed);
        }
        let envelope = traversal.envelope();
        // A later page whose send failed is recorded as a network failure; a
        // traversal that stopped for any other reason settles with the last
        // admitted exchange's facts.
        if network_failure {
            lease
                .finish(Outcome::NetworkFailure)
                .map_err(|_| err("governor_denied", "settlement failed"))?;
        } else {
            settle(lease, last.0, last.1.as_deref(), last.2, last.3)?;
        }
        Ok(envelope)
    }
}
fn admit_response(
    response: ReadResponse<'_>,
    contains_secret: &dyn Fn(&[u8]) -> bool,
    key: &[u8; 16],
    req: &ReadRequest,
) -> Result<Value, Error> {
    let ReadResponse {
        bytes,
        ct,
        status,
        challenge,
        body_failed,
        assessment,
    } = response;
    let screening = response_screening(bytes, ct, contains_secret);
    let safe_ct = ct.filter(|value| !contains_secret(value.as_bytes()));
    let (value, fields) = if assessment == crate::html::ChallengeAssessment::Clear {
        match screening {
            ResponseScreening::Echo => (withheld_fallback(bytes, safe_ct), SourceFields::default()),
            ResponseScreening::Unreviewable => {
                (unreviewed_fallback(bytes, safe_ct), SourceFields::default())
            }
            ResponseScreening::Clear => decode_response_with_fields(bytes, ct, key),
        }
    } else {
        (Value::Null, SourceFields::default())
    };
    let mut decoded = PrivateValue(value);
    if matches!(screening, ResponseScreening::Clear)
        && projected_source_carries_secret(&decoded, fields, contains_secret)
    {
        decoded = PrivateValue(withheld_fallback(bytes, safe_ct));
    }
    if matches!(req, ReadRequest::Courses(_))
        && decoded["result"] == "success"
        && parse_page(&decoded["data"]).is_err()
    {
        decoded = PrivateValue(fallback(bytes, ct, "invalid_pagination_contract"));
    }
    if challenge || matches!(status, 401 | 403 | 429) {
        return Err(err("safety_denied", "access denied; no retry"));
    }
    if body_failed {
        return Err(err("body_limit", "response incomplete or oversized"));
    }
    if status != 200 {
        return Err(err("http_error", "upstream HTTP failure"));
    }
    if assessment == crate::html::ChallengeAssessment::Unreviewed {
        return Err(err(
            "response_safety_unreviewed",
            "response body safety could not be established; admission refused without retry",
        ));
    }
    Ok(std::mem::take(&mut decoded.0))
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteOperation {
    Select,
    Cancel,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteIntent {
    pub operation: WriteOperation,
    pub course_id: String,
    pub owner_present: bool,
}
pub fn preview_write(intent: &WriteIntent) -> Value {
    json!({"result":"blocked","intent":intent,"reason":"缺少选/退课端点与载荷的上游证据","confirmation_available":false,"write_performed":false})
}
struct RunInput {
    operation: RunOperation,
    payload: Option<RunPayload>,
}
impl<'de> Deserialize<'de> for RunInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            operation: RunOperation,
            #[serde(default, deserialize_with = "optional_object")]
            payload: Option<RunPayload>,
        }
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON object")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                _: A,
            ) -> Result<Self::Value, A::Error> {
                Err(serde::de::Error::custom("positional input refused"))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                access: A,
            ) -> Result<Self::Value, A::Error> {
                serde::de::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(
                    access,
                ))
            }
        }
        deserializer.deserialize_map(Visitor).map(|strict| Self {
            operation: strict.operation,
            payload: strict.payload,
        })
    }
}
#[derive(Default, Deserialize)]
struct RunPayload {
    auth_token: Option<Secret>,
    final_token_url: Option<Secret>,
    query: Option<RunQuery>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum RunQuery {
    Page(PageRequest),
    Date(DateRequest),
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunOperation {
    Profile,
    SemesterCourses,
    Selectable,
    Chosen,
    Config,
    Statistics,
    PreviewWrite,
}
/// Envelope admission is strict; payload is arbitrary JSON so invalid/missing
/// operation-specific material is reported as structured blocked, not a panic.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    let result = (|| -> Result<Value, Error> {
        let input: RunInput = serde_json::from_str(input).map_err(|_| {
            err(
                "invalid_input",
                "expected operation and optional JSON payload only",
            )
        })?;
        if matches!(input.operation, RunOperation::PreviewWrite) {
            return Ok(
                json!({"result":"blocked","reason":"缺少选/退课端点与载荷的上游证据","confirmation_available":false,"write_performed":false}),
            );
        }
        if !online {
            return Ok(
                json!({"result":"blocked","reason":"online permission required; no request made"}),
            );
        }
        let mut p = input.payload.unwrap_or_default();
        let token = if let Some(url) = p.final_token_url.take() {
            auth_token(&url.0)?
        } else {
            p.auth_token
                .take()
                .filter(|value| !value.0.is_empty())
                .ok_or_else(|| {
                    err(
                        "login_required",
                        "auth_token or final_token_url required via stdin",
                    )
                })?
                .0
        };
        let req = request_for(input.operation, p)?;
        BoyaClient::open()?.read(&token, &req)
    })();
    Ok(match result {
        Ok(v) => v,
        Err(e) => json!({"result":"blocked","reason":e.code}),
    })
}

/// Map one admitted operation plus its payload to the fixed read request.
fn request_for(operation: RunOperation, payload: RunPayload) -> Result<ReadRequest, Error> {
    Ok(match operation {
        RunOperation::Profile => ReadRequest::Profile,
        RunOperation::Selectable => ReadRequest::Selectable,
        RunOperation::Config => ReadRequest::Config,
        RunOperation::Statistics => ReadRequest::Statistics,
        RunOperation::SemesterCourses => ReadRequest::Courses(match payload.query {
            Some(RunQuery::Page(query)) => query,
            _ => {
                return Err(err(
                    "invalid_input",
                    "query requires pageNumber and pageSize",
                ));
            }
        }),
        RunOperation::Chosen => ReadRequest::Chosen(match payload.query {
            Some(RunQuery::Date(query)) => query,
            _ => return Err(err("invalid_input", "query requires startDate and endDate")),
        }),
        RunOperation::PreviewWrite => {
            return Err(err(
                "unsupported",
                "write operations stay blocked; no request was sent",
            ));
        }
    })
}

/// Strict object-root input for one explicit CAS login plus one selected read.
struct SessionInput {
    authorized: bool,
    username: String,
    password: String,
    intent: String,
    read: SessionRead,
}
impl<'de> Deserialize<'de> for SessionInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            authorized: bool,
            username: String,
            password: String,
            intent: String,
            read: SessionRead,
        }
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SessionInput;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON object")
            }
            // `deny_unknown_fields` alone still admits a positional array, so
            // a sequence root is refused before any field is read.
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                _: A,
            ) -> Result<Self::Value, A::Error> {
                Err(serde::de::Error::custom("positional input refused"))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                access: A,
            ) -> Result<Self::Value, A::Error> {
                let strict =
                    Strict::deserialize(serde::de::value::MapAccessDeserializer::new(access))?;
                Ok(SessionInput {
                    authorized: strict.authorized,
                    username: strict.username,
                    password: strict.password,
                    intent: strict.intent,
                    read: strict.read,
                })
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRead {
    operation: RunOperation,
    #[serde(default)]
    query: Option<RunQuery>,
}

/// One explicit in-memory CAS login followed by one Boya read. A
/// `semester_courses` read may traverse the caller-declared `maxPages` pages
/// under that same lease; every other operation is one request. The issued
/// token is consumed by that read and never persisted, refreshed or reused by
/// a later invocation.
pub fn session(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > 65536 {
        return Err(err("invalid_input", "request too large"));
    }
    let request: SessionInput = serde_json::from_str(input)
        .map_err(|_| err("invalid_input", "expected strict session object"))?;
    if !request.authorized {
        return Err(err(
            "permission",
            "explicit authorization for one Boya authentication attempt is required",
        ));
    }
    if request.intent != format!("LOGIN {} boya", request.username) {
        return Err(err("invalid_input", "authentication intent does not match"));
    }
    let read = request.read;
    if matches!(read.operation, RunOperation::PreviewWrite) {
        return Err(err(
            "unsupported",
            "write operations stay blocked; no request was sent",
        ));
    }
    let req = request_for(
        read.operation,
        RunPayload {
            query: read.query,
            auth_token: None,
            final_token_url: None,
        },
    )?;
    if !online {
        return Err(err(
            "online_required",
            "Boya sessions require explicit online permission; no authentication was attempted",
        ));
    }
    let username = Zeroizing::new(request.username);
    let password = Zeroizing::new(request.password);
    let credentials = cas::SsoCredentials::new(&username, &password)
        .map_err(|_| err("invalid_input", "credentials are not admissible"))?;
    let client = cas::http_client().map_err(|_| err("transport", "HTTPS initialization failed"))?;
    let governor =
        Governor::open().map_err(|_| err("governor_denied", "shared governor unavailable"))?;
    let mut lease = net::acquire_kind(&governor, crate::governor::RequestKind::Authentication)
        .map_err(|_| err("governor_denied", "request admission unavailable"))?;
    let authenticated =
        cas::authenticate_service(&mut lease, &client, cas::CasService::Boya, credentials);
    let mut session = match authenticated {
        Ok(session) => session,
        Err(failure) => {
            // Settle the durable attempt: an unsettled outcome blocks every
            // later authentication until an offline operator review.
            let settled = match failure.code {
                "auth_latched" => lease.finish(Outcome::CredentialRejected),
                "challenge_requires_human" => lease.finish(Outcome::CaptchaRequired),
                "network_error" | "body_limit" => lease.finish(Outcome::NetworkFailure),
                _ => lease.finish_without_request(),
            };
            settled.map_err(|_| {
                err(
                    "governor_denied",
                    "cannot settle the Boya authentication attempt",
                )
            })?;
            return Err(failure);
        }
    };
    let token = session.take_service_credential().map_err(|_| {
        err(
            "authentication_unconfirmed",
            "the Boya handoff supplied no admitted token; no read was sent",
        )
    })?;
    // Build the read before booking the follow-up slot so a malformed request
    // never consumes an admitted request.
    let (request, key) = BoyaClient::prepare(&client, &token, &req)?;
    let reservation = lease
        .reserve_followup()
        .map_err(|_| err("governor_denied", "cannot admit the Boya follow-up read"))?;
    if !reservation.cooldown_wait.is_zero() {
        return Err(err(
            "cooldown",
            "the Boya read was deferred; no retry was performed",
        ));
    }
    if !reservation.request_wait.is_zero() {
        std::thread::sleep(reservation.request_wait);
    }
    // The authentication session stays alive for the whole read: its retained
    // credentials — every cookie value of every scope, the replaced and
    // expired values, and the transmitted Cookie headers — screen the raw
    // and decoded responses alongside the issued token and the submitted
    // password. Nothing the session or a response issued is adopted,
    // persisted or transmitted.
    BoyaClient::execute(
        &client,
        lease,
        request,
        key,
        ScreenedSecrets {
            token: token.as_str(),
            session: Some(&session),
            password: Some(password.as_str()),
            issued: IssuedCookies::default(),
        },
        &req,
    )
}
pub fn schema() -> Value {
    let mut s = json!({"module":"boya","state":"partial-offline","state_detail":"the offline session/read path and the bounded pagination traversal are implemented and offline-tested; one authenticated live session reached the read path and its response was withheld when it issued a session cookie; no admitted decoded live course list, complete live pagination or owner-present mutation has been observed","input":{"type":"object","additionalProperties":false,"required":["operation"],"properties":{"operation":{"enum":["profile","semester_courses","selectable","chosen","config","statistics","preview_write"]},"payload":{}}},"payload_policy":"arbitrary JSON admitted; missing/invalid operation-specific fields produce structured blocked","output":{"type":"object","required":["result"],"properties":{"result":{"enum":["success","partial","upstream_error","fallback","blocked"]},"list_contract":{"enum":["page","whole_list"],"description":"List operations only. page is queryStudentSemesterCourseByPage; whole_list is queryChosenCourse, whose source contract declares no pagination."},"complete":{"type":"boolean","description":"List operations only. True only when every element the source declared for the requested window was collected in this invocation; false when the traversal stopped early, and then incomplete_reason says why."},"incomplete_reason":{"type":["string","null"],"description":"Why the traversal stopped before the declared set was collected: page_bound_reached (the caller's maxPages), empty_page, declared_pages_exhausted, pagination_page_mismatch, pagination_changed, pagination_inconsistent, invalid_pagination_contract, duplicate_course_id, entry_id_unconfirmed, list_contract_unrecognized, source_page_not_success, governor_cooldown or a local preflight code. Null when complete."},"entries":{"type":["array","null"],"description":"Admitted list records in source order, deduplicated by source id; null when the declared list contract itself was not recognized."},"entry_count":{"type":["integer","null"]},"pagination":{"type":["object","null"],"description":"semester_courses only: the caller's start page, page size and max_pages bound, each admitted page's declared number/count/size/totals, the source-declared page size, total elements and total pages, and pages_fetched. Null for chosen because that source declares no pagination."},"page_failure":{"description":"The first admitted page whose own result was not success, verbatim, so degraded evidence or an upstream error is not lost."},"fallback_reason":{"type":"string"},"raw_evidence":{"type":"object"}}},"writes":"blocked: missing authoritative endpoint and payload","login":"boya session performs one explicit in-memory CAS login for a caller token then one read operation; a semester_courses read traverses at most the caller-declared maxPages declared pages; the issued token is consumed once and never persisted or refreshed"});
    s["pagination"] = json!({"applies_to":["semester_courses"],"request":{"maxPages":{"type":"integer","minimum":1,"maximum":MAX_TRAVERSAL_PAGES,"default":1,"description":"Caller-declared bound on how many pages one invocation may request. It is never sent upstream and is never a claim about the source's page count."}},"bound":"A traversal requests at most maxPages pages under one lease and never a page beyond the source-declared totalPages. No page count or page base is inferred: the mapping between the requested page number and the source's declared number is learned from the first admitted page and then required, and every page must repeat the same declared totals and page size.","stops":"Done at the last declared page (declared number + 1 >= totalPages), when the declared totalElements have been collected, or on an empty page. Early stops keep the admitted records and report complete=false with the reason.","refusals":["a page does not answer the requested position under the mapping declared by the first page","totalElements/totalPages/size changed between pages","an intermediate page is not a full page of the declared size","the collected items exceed the declared totalElements","duplicate source id","entry without a numeric source id","a page whose own result is not success","governor cooldown before the next page"],"complete":"complete=true means every declared element of the list was collected in this traversal; it does not claim elements before the requested start page.","whole_list":{"applies_to":["chosen"],"description":"queryChosenCourse returns the complete courseList for the requested date window and declares no pagination metadata; exactly one request is made and complete reflects only that declared list contract. No page count is inferred."}});
    s["input"]["properties"]["payload"] = json!({"description":"operation-specific; semester_courses accepts pageNumber, pageSize and the local-only maxPages (1..=20, default 1), chosen accepts startDate and endDate, preview_write stays blocked"});
    s["pagination"]["acquisition"] = json!(
        "A later page whose send fails stops the traversal with incomplete_reason network_error and records the observed network failure; a refusal on a later page settles the lease and returns its typed error. No page is retried or renumbered, and admitted records from earlier pages stay in the envelope."
    );
    s["output"]["properties"]["data"] = json!({"description":"queryChosenCourse only: the admitted source payload when the declared courseList contract was not recognized, so the response is not lost; it is never fabricated."});
    s["session"] = json!({"description":"One explicit in-memory CAS login to bykc followed by exactly one sscv read; no persistence, refresh, retry, writes or cookie adoption.","input":{"type":"object","additionalProperties":false,"required":["authorized","username","password","intent","read"],"properties":{"authorized":{"type":"boolean"},"username":{"type":"string"},"password":{"type":"string"},"intent":{"type":"string"},"read":{"type":"object","additionalProperties":false,"required":["operation"],"properties":{"operation":{"enum":["profile","semester_courses","selectable","chosen","config","statistics"]},"query":{"type":"object"}}}}},"intent":"LOGIN <username> boya","output":"decrypted read result, or degraded/fallback with raw evidence and fallback_reason, or sensitive_response_withheld; writes remain blocked","validation":"object root only; read must be enabled; enabled read requires authorized=true, exact intent and --online before transport or admission"});
    // The session read keeps the same one-lease contract; only the traversal
    // bound and the completeness reporting are added.
    s["session"]["description"] = json!(
        "One explicit in-memory CAS login to bykc followed by one sscv read operation; a semester_courses read may traverse at most the caller-declared maxPages declared pages under the same lease; no persistence, refresh, retry, writes or cookie adoption. Cookie values that read responses issue are retained only as in-memory screening secrets and are never persisted or transmitted."
    );
    s["session"]["output"] = json!(
        "decrypted read result, or a paginated list envelope with complete/incomplete_reason, or degraded/fallback with raw evidence and fallback_reason, or sensitive_response_withheld; writes remain blocked"
    );
    s["session"]["validation"] = json!(
        "object root only; read must be enabled; enabled read requires authorized=true, exact intent and --online before transport or admission; read.query.maxPages must be 1..=20 and bounds only a semester_courses traversal"
    );
    s
}
#[cfg(test)]
mod numeric_admission_proof {
    use super::*;

    fn admit(plain: &[u8], secret: &str, status: u16, challenge: bool) -> Result<Value, Error> {
        let key = [0u8; 16];
        let wire = STANDARD.encode(aes(plain, &key, true).unwrap().as_slice());
        admit_response(
            ReadResponse {
                bytes: wire.as_bytes(),
                ct: Some("text/plain"),
                status,
                challenge,
                body_failed: false,
                assessment: crate::html::assess_challenge_body(
                    wire.as_bytes(),
                    Some("text/plain"),
                    true,
                ),
            },
            &|candidate| net::carries_secret(candidate, secret),
            &key,
            &ReadRequest::Profile,
        )
    }

    pub fn boolean_credential() {
        let value = admit(
            br#"{"status":"0","token":null,"data":false}"#,
            "false",
            200,
            false,
        )
        .unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert!(value.get("data").is_none());
    }

    pub fn numeric_credential() {
        let value = admit(
            br#"{"status":"0","token":null,"data":1e3}"#,
            "1000.0",
            200,
            false,
        )
        .unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert!(value.get("data").is_none());
    }

    pub fn controls_and_denials() {
        let body = br#"{"status":"0","token":null,"data":false}"#;
        assert_eq!(
            admit(body, "unrelated-secret", 200, false).unwrap(),
            json!({"result":"success","data":false})
        );
        let number = br#"{"status":"0","token":null,"data":42}"#;
        assert_eq!(
            admit(number, "unrelated-secret", 200, false).unwrap(),
            json!({"result":"success","data":42})
        );
        for (status, challenge) in [(401, false), (403, false), (429, false), (200, true)] {
            assert_eq!(
                admit(body, "false", status, challenge).unwrap_err().code,
                "safety_denied"
            );
        }
    }

    pub fn generated_fallback_metadata_is_not_an_echo() {
        let wire = b"YWJj";
        let value = admit_response(
            ReadResponse {
                bytes: wire,
                ct: Some("text/plain"),
                status: 200,
                challenge: false,
                body_failed: false,
                assessment: crate::html::assess_challenge_body(wire, Some("text/plain"), true),
            },
            &|candidate| net::carries_secret(candidate, "false"),
            &[0u8; 16],
            &ReadRequest::Profile,
        )
        .unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(
            value["fallback_reason"],
            "base64_aes_json_contract_unrecognized"
        );
        assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(wire));
        assert_eq!(value["raw_evidence"]["raw_withheld"], false);
    }

    pub fn upstream_error_scalar_is_still_screened() {
        let value = admit(br#"{"status":"9","data":false}"#, "false", 200, false).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert!(value["raw_evidence"]["data"].is_null());
    }

    pub fn missing_fields_are_not_source_nulls() {
        let success = admit(br#"{"status":"0"}"#, "null", 200, false).unwrap();
        assert_eq!(success["result"], "success");
        assert!(success["data"].is_null());
        let error = admit(br#"{"status":"9","data":42}"#, "null", 200, false).unwrap();
        assert_eq!(error["result"], "upstream_error");
        assert_eq!(error["data"], 42);
        assert!(error["errmsg"].is_null());
    }

    pub fn explicit_source_null_is_screened() {
        let value = admit(br#"{"status":"0","data":null}"#, "null", 200, false).unwrap();
        assert_eq!(value["result"], "fallback");
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert!(value["raw_evidence"]["data"].is_null());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boolean_scalar_credential_is_withheld() {
        numeric_admission_proof::boolean_credential();
    }
    #[test]
    fn numeric_scalar_credential_is_withheld() {
        numeric_admission_proof::numeric_credential();
    }
    #[test]
    fn scalar_controls_and_safety_denials_are_retained() {
        numeric_admission_proof::controls_and_denials();
    }
    #[test]
    fn generated_fallback_metadata_is_not_an_echo() {
        numeric_admission_proof::generated_fallback_metadata_is_not_an_echo();
    }
    #[test]
    fn upstream_error_scalar_is_still_screened() {
        numeric_admission_proof::upstream_error_scalar_is_still_screened();
    }
    #[test]
    fn missing_fields_are_not_source_nulls() {
        numeric_admission_proof::missing_fields_are_not_source_nulls();
    }
    #[test]
    fn explicit_source_null_is_screened() {
        numeric_admission_proof::explicit_source_null_is_screened();
    }
    #[test]
    fn production_admission_withholds_cookies_and_encoded_credentials() {
        let key = [0u8; 16];
        let mut secrets = ScreenedSecrets {
            token: "abc_123",
            session: None,
            password: None,
            issued: IssuedCookies::default(),
        };
        let admit = |plain: &[u8], secrets: &ScreenedSecrets<'_>| {
            let wire = STANDARD.encode(aes(plain, &key, true).unwrap().as_slice());
            let wire = Zeroizing::new(wire);
            let assessment =
                crate::html::assess_challenge_body(wire.as_bytes(), Some("text/plain"), true);
            admit_response(
                ReadResponse {
                    bytes: wire.as_bytes(),
                    ct: Some("text/plain"),
                    status: 200,
                    challenge: false,
                    body_failed: false,
                    assessment,
                },
                &|candidate| secrets.carries(candidate),
                &key,
                &ReadRequest::Profile,
            )
        };
        let mut headers = reqwest::header::HeaderMap::new();
        let safe = br#"{"status":"0","data":{"value":"q"}}"#;
        assert_eq!(admit(safe, &secrets).unwrap()["data"]["value"], "q");
        headers.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static("x=opaque-issued-value"),
        );
        // A reviewed Set-Cookie issuance is admitted: the value joins the
        // invocation's privacy guard only, never a jar or a later request.
        secrets.issued.absorb(&headers).unwrap();
        assert_eq!(admit(safe, &secrets).unwrap()["data"]["value"], "q");
        // Literal and percent-encoded echoes of the issued value are
        // withheld from the projected output, while unrelated data stays.
        assert_eq!(
            admit(
                br#"{"status":"0","data":{"note":"opaque-issued-value"}}"#,
                &secrets
            )
            .unwrap()["fallback_reason"],
            "sensitive_response_withheld"
        );
        assert_eq!(
            admit(
                br#"{"status":"0","data":{"note":"opaque%2Dissued%2Dvalue"}}"#,
                &secrets
            )
            .unwrap()["fallback_reason"],
            "sensitive_response_withheld"
        );
        let opaque = br#"{"status":"0","data":"freshopaque123"}"#;
        assert_eq!(admit(opaque, &secrets).unwrap()["data"], "freshopaque123");
        headers.clear();
        for plain in [
            br#"{"status":"0","data":"YWJjXzEyMw=="}"#.as_slice(),
            br#"{"status":"0","data":"%61%62%63%5F%31%32%33"}"#.as_slice(),
            br#"{"status":"0","data":"\u0059WJjXzEyMw=="}"#.as_slice(),
            br#"{"status":"0","data":"\u002561%62%63%5F%31%32%33"}"#.as_slice(),
            br#"{"status":"0","data":{"\u0059WJjXzEyMw==":"ordinary"}}"#.as_slice(),
        ] {
            let value = admit(plain, &secrets).unwrap();
            assert_eq!(value["raw_evidence"]["data"], Value::Null);
            assert_ne!(value["result"], "success");
        }
        // A truncated ciphertext would otherwise be returned as raw fallback.
        let wire = Zeroizing::new(STANDARD.encode([0u8; 15]));
        let admit_wire = |secrets: &ScreenedSecrets<'_>| {
            admit_response(
                ReadResponse {
                    bytes: wire.as_bytes(),
                    ct: Some("text/plain"),
                    status: 200,
                    challenge: false,
                    body_failed: false,
                    assessment: crate::html::assess_challenge_body(
                        wire.as_bytes(),
                        Some("text/plain"),
                        true,
                    ),
                },
                &|candidate| secrets.carries(candidate),
                &key,
                &ReadRequest::Profile,
            )
        };
        assert_eq!(
            admit_wire(&secrets).unwrap()["raw_evidence"]["data"],
            STANDARD.encode(wire.as_bytes())
        );
        headers.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static("x=wire-issued-value"),
        );
        // Issued values keep screening raw fallback bytes too: the wire is
        // still published only when it carries none of the invocation's
        // secrets.
        secrets.issued.absorb(&headers).unwrap();
        assert_eq!(
            admit_wire(&secrets).unwrap()["raw_evidence"]["data"],
            STANDARD.encode(wire.as_bytes())
        );
        for (status, challenge) in [(401, false), (403, false), (200, true)] {
            let denied = admit_response(
                ReadResponse {
                    bytes: wire.as_bytes(),
                    ct: Some("text/plain"),
                    status,
                    challenge,
                    body_failed: false,
                    assessment: crate::html::assess_challenge_body(
                        wire.as_bytes(),
                        Some("text/plain"),
                        true,
                    ),
                },
                &|candidate| secrets.carries(candidate),
                &key,
                &ReadRequest::Profile,
            );
            assert_eq!(denied.unwrap_err().code, "safety_denied");
        }
    }

    /// Admit one synthetic encrypted body the way `exchange` does: the
    /// response's own `Set-Cookie` values are reviewed into the
    /// invocation guard first, then the raw and decoded material is
    /// screened against every secret the invocation has handled.
    fn cookie_admit(
        plain: &[u8],
        secrets: &ScreenedSecrets<'_>,
        key: &[u8; 16],
    ) -> Result<Value, Error> {
        let wire = Zeroizing::new(STANDARD.encode(aes(plain, key, true).unwrap().as_slice()));
        admit_response(
            ReadResponse {
                bytes: wire.as_bytes(),
                ct: Some("text/plain"),
                status: 200,
                challenge: false,
                body_failed: false,
                assessment: crate::html::assess_challenge_body(
                    wire.as_bytes(),
                    Some("text/plain"),
                    true,
                ),
            },
            &|candidate| secrets.carries(candidate),
            key,
            &ReadRequest::Profile,
        )
    }

    #[test]
    fn issued_cookies_are_screened_across_a_traversal() {
        let key = [0u8; 16];
        let token = "synthetic-auth-token-value";
        // The handoff jar absorbed the first SID declaration, then a
        // replacement of the same name/path, exactly the sequence the login
        // exchange produces: the earlier value is retired but stays in the
        // privacy guard of the attempt.
        let session = cas::ServiceSession::test_session_with_cookies(
            cas::CasService::Boya,
            "https://bykc.buaa.edu.cn/",
            &[
                "SID=previous-auth-cookie; Path=/",
                "SID=current-auth-cookie; Path=/",
            ],
        );
        assert!(session.contains_secret_bytes(b"echo current-auth-cookie"));
        assert!(session.contains_secret_bytes(b"echo previous-auth-cookie"));
        assert!(!session.contains_secret_bytes(b"ordinary material"));
        let mut secrets = ScreenedSecrets {
            token,
            session: Some(&session),
            password: Some("synthetic-auth-password"),
            issued: IssuedCookies::default(),
        };
        let ordinary = br#"{"status":"0","data":{"name":"ordinary"}}"#;
        // An ordinary HTTP 200 that issues a session cookie is admitted:
        // issuance is not a challenge, only its value is retained.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static("PAGE=first-page-cookie; Path=/"),
        );
        secrets.issued.absorb(&headers).unwrap();
        assert_eq!(
            cookie_admit(ordinary, &secrets, &key).unwrap()["data"]["name"],
            "ordinary"
        );
        // A later page issues another value; the first stays in the guard.
        headers.clear();
        headers.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_static("PAGE2=\"quoted-page-cookie\"; Path=/"),
        );
        secrets.issued.absorb(&headers).unwrap();
        // Decoded echoes of every credential the invocation has handled are
        // withheld: the auth token, the live and the replaced jar cookies,
        // the earlier page's issued value, and both spellings of the quoted
        // issued value.
        for plain in [
            br#"{"status":"0","data":{"note":"synthetic-auth-token-value"}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"synthetic-auth-password"}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"current-auth-cookie"}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"previous-auth-cookie"}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"first-page-cookie"}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"first%2Dpage%2Dcookie"}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"\"quoted-page-cookie\""}}"#.as_slice(),
            br#"{"status":"0","data":{"note":"quoted-page-cookie"}}"#.as_slice(),
        ] {
            let value = cookie_admit(plain, &secrets, &key).unwrap();
            assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
            assert_eq!(value["raw_evidence"]["data"], Value::Null);
            assert!(value.get("data").is_none());
        }
        // Ordinary data carrying none of the secrets is still admitted.
        assert_eq!(
            cookie_admit(ordinary, &secrets, &key).unwrap()["data"]["name"],
            "ordinary"
        );
    }

    /// One in-process HTTP server that captures each request and replies
    /// with scripted headers and body. The same fixture shape as the
    /// departments/gateway loopback tests: nonblocking listener, bounded
    /// read, full request body consumed before replying.
    struct Server {
        address: std::net::SocketAddr,
        requests: std::sync::mpsc::Receiver<String>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl Server {
        fn new(handler: impl FnMut(&mut std::net::TcpStream, usize) + Send + 'static) -> Self {
            use std::io::Read;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, requests) = std::sync::mpsc::channel();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_stop = std::sync::Arc::clone(&stop);
            let worker = std::thread::spawn(move || {
                let mut handler = handler;
                let mut index = 0usize;
                while !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            socket
                                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                                .unwrap();
                            let mut bytes = Vec::new();
                            let mut byte = [0u8];
                            while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 64 * 1024 {
                                match socket.read(&mut byte) {
                                    Ok(1) => bytes.push(byte[0]),
                                    _ => break,
                                }
                            }
                            let request = String::from_utf8_lossy(&bytes).into_owned();
                            let body_len: usize = request
                                .lines()
                                .find_map(|line| {
                                    line.strip_prefix("Content-Length: ")
                                        .and_then(|value| value.trim().parse().ok())
                                })
                                .unwrap_or(0);
                            if body_len > 0 {
                                socket.read_exact(&mut vec![0u8; body_len]).unwrap();
                            }
                            sender.send(request).unwrap();
                            handler(&mut socket, index);
                            index += 1;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(2))
                        }
                        Err(error) => panic!("loopback listener failed: {error}"),
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
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }

    /// Two real exchanges against a loopback server prove the production
    /// path: the first response's `Set-Cookie` value is admitted and
    /// retained by the invocation guard, the second request still carries
    /// no `Cookie` header, and a second response that echoes the issued
    /// value is withheld rather than admitted.
    #[test]
    fn issued_cookie_never_returns_and_its_echo_is_withheld() {
        use std::io::Write;
        use std::os::unix::fs::DirBuilderExt;
        let key = [0u8; 16];
        let ordinary = STANDARD.encode(
            aes(br#"{"status":"0","data":{"name":"ordinary"}}"#, &key, true)
                .unwrap()
                .as_slice(),
        );
        let echoed = STANDARD.encode(
            aes(
                br#"{"status":"0","data":{"note":"loop-issued-cookie-value"}}"#,
                &key,
                true,
            )
            .unwrap()
            .as_slice(),
        );
        let server = Server::new(move |socket, index| {
            let (extra, body) = match index {
                0 => (
                    "Set-Cookie: PAGE=loop-issued-cookie-value; Path=/\r\n",
                    ordinary.as_str(),
                ),
                _ => ("", echoed.as_str()),
            };
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
                body.len(),
                extra,
                body
            )
            .unwrap();
        });
        let client = reqwest::blocking::Client::builder()
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "boya-exchange-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let governor = Governor::isolated_for_test(&path).unwrap();
        let mut lease = net::acquire(&governor).unwrap();
        let token = "synthetic-auth-token-value";
        let mut secrets = ScreenedSecrets {
            token,
            session: None,
            password: None,
            issued: IssuedCookies::default(),
        };
        // Prepared production requests are only re-pointed at the loopback
        // listener; every header the real client sends stays unchanged.
        let route = |request: &mut reqwest::blocking::Request| {
            let url = request.url_mut();
            url.set_scheme("http").expect("test loopback scheme");
            url.set_host(Some(&server.address.ip().to_string()))
                .expect("test loopback host");
            url.set_port(Some(server.address.port()))
                .expect("test loopback port");
        };
        let mut first = BoyaClient::prepare(&client, token, &ReadRequest::Profile)
            .unwrap()
            .0;
        route(&mut first);
        // The loopback server encrypts with the test key, so exchange is
        // given that key instead of the per-request key `prepare` generated.
        let first = BoyaClient::exchange(
            &client,
            &mut lease,
            first,
            Zeroizing::new(key),
            &mut secrets,
            &ReadRequest::Profile,
        )
        .map_err(|_| err("test_exchange", "first exchange transport failed"))
        .unwrap();
        assert_eq!(
            first.value.unwrap()["data"]["name"],
            "ordinary",
            "an ordinary cookie-issuing response is admitted"
        );
        assert!(secrets.issued.carries(b"loop-issued-cookie-value"));
        // The traversal reserves the follow-up on the same lease before the
        // next exchange; the reserved pacing sleep is not part of the test.
        let reservation = lease.reserve_followup().unwrap();
        assert!(reservation.cooldown_wait.is_zero());
        let mut second = BoyaClient::prepare(&client, token, &ReadRequest::Profile)
            .unwrap()
            .0;
        route(&mut second);
        let second = BoyaClient::exchange(
            &client,
            &mut lease,
            second,
            Zeroizing::new(key),
            &mut secrets,
            &ReadRequest::Profile,
        )
        .map_err(|_| err("test_exchange", "second exchange transport failed"))
        .unwrap();
        let value = second.value.unwrap();
        assert_eq!(value["fallback_reason"], "sensitive_response_withheld");
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        settle(
            lease,
            second.status,
            second.retry_after.as_deref(),
            second.challenge,
            second.body_failed,
        )
        .unwrap();
        for request_text in [
            server
                .requests
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            server
                .requests
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
        ] {
            assert!(
                !request_text
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("cookie:")),
                "an issued value must never be retransmitted"
            );
            assert!(
                request_text.contains("auth_token: synthetic-auth-token-value"),
                "the token header stays unchanged"
            );
        }
        assert!(!governor.status().unwrap().safety_latched);
        drop(governor);
        std::fs::remove_dir_all(path).unwrap();
    }

    /// The consumer invariant for unscreened bodies: a cookie-issuing HTTP
    /// 200 whose plaintext body cannot be parsed for privacy screening must
    /// never publish raw evidence when an escaped spelling of a retained
    /// secret appears in it, while a harmless unparseable body keeps its
    /// exact original bytes in base64. The first case is the control the
    /// generic escape heuristic already covers; the second decodes to the
    /// issued value without any byte the heuristic recognizes. The last two
    /// hold the same recoverable escaped value inside literals a strict
    /// decoder rejects entirely: one cut off before its closing quote and
    /// one followed by an invalid escape.
    #[test]
    fn escaped_issued_value_in_unparseable_body_is_withheld() {
        use std::io::Write;
        use std::os::unix::fs::DirBuilderExt;
        let escaped_unicode = br#"{"note":"\u0061bc_123","note":"ordinary"}"#.as_slice();
        let escaped_solidus = br#"{"note":"abc\/123","note":"ordinary"}"#.as_slice();
        let harmless = br#"{"note":"ordinary","note":"ordinary"}"#.as_slice();
        let unterminated = br#"{"note":"abc\/123"#.as_slice();
        let invalid_escape = br#"{"note":"abc\/123\q"}"#.as_slice();
        let harmless_escaped = br#"{"note":"abc\/124","note":"ordinary"}"#.as_slice();
        let server = Server::new(move |socket, index| {
            let (extra, body): (&'static str, &[u8]) = match index {
                0 => ("Set-Cookie: sid=abc_123; Path=/\r\n", escaped_unicode),
                1 => ("Set-Cookie: sid=abc/123; Path=/\r\n", escaped_solidus),
                2 => ("", harmless),
                3 => ("", unterminated),
                4 => ("", invalid_escape),
                _ => ("", harmless_escaped),
            };
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
                        body.len(),
                        extra
                    )
                    .as_bytes(),
                )
                .unwrap();
            socket.write_all(body).unwrap();
        });
        let client = reqwest::blocking::Client::builder()
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "boya-escaped-echo-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let governor = Governor::isolated_for_test(&path).unwrap();
        let mut lease = net::acquire(&governor).unwrap();
        let token = "synthetic-auth-token-value";
        let mut secrets = ScreenedSecrets {
            token,
            session: None,
            password: None,
            issued: IssuedCookies::default(),
        };
        let route = |request: &mut reqwest::blocking::Request| {
            let url = request.url_mut();
            url.set_scheme("http").expect("test loopback scheme");
            url.set_host(Some(&server.address.ip().to_string()))
                .expect("test loopback host");
            url.set_port(Some(server.address.port()))
                .expect("test loopback port");
        };
        let key = [0u8; 16];
        let mut values = Vec::new();
        let mut last = None;
        for _ in 0..6 {
            if !values.is_empty() {
                let reservation = lease.reserve_followup().unwrap();
                assert!(reservation.cooldown_wait.is_zero());
            }
            let mut request = BoyaClient::prepare(&client, token, &ReadRequest::Profile)
                .unwrap()
                .0;
            route(&mut request);
            let exchange = BoyaClient::exchange(
                &client,
                &mut lease,
                request,
                Zeroizing::new(key),
                &mut secrets,
                &ReadRequest::Profile,
            )
            .map_err(|_| err("test_exchange", "exchange transport failed"))
            .unwrap();
            let Exchange {
                value,
                status,
                retry_after,
                challenge,
                body_failed,
            } = exchange;
            last = Some((status, retry_after, challenge, body_failed));
            values.push(value);
        }
        let (last_status, last_retry, last_challenge, last_body_failed) = last.unwrap();
        let mut values = values.into_iter();
        // Control: the `\u0061` spelling is already caught by the generic
        // escape heuristic, so its raw data stays withheld.
        let value = values.next().unwrap().unwrap();
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        // A `\/` escape contains no byte the heuristic recognizes and the
        // duplicate key rejects the privacy parse: the decoded value is the
        // issued cookie, so the raw data must be withheld.
        let value = values.next().unwrap().unwrap();
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        // Harmless control: the same unparseable shape carrying no secret
        // preserves the exact source bytes in base64.
        let value = values.next().unwrap().unwrap();
        assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(harmless));
        // An escaped cookie spelling the literal scan cannot terminate is
        // still recoverable credential material: the raw data must be
        // withheld rather than published.
        let value = values.next().unwrap().unwrap();
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        // The same escaped value followed by an invalid escape is equally
        // recoverable by a lenient consumer; it must not publish either.
        let value = values.next().unwrap().unwrap();
        assert_eq!(value["raw_evidence"]["data"], Value::Null);
        // A harmless escaped literal that decodes cleanly is not a
        // disclosure even next to a similar retained value: the exact
        // source bytes stay published.
        let value = values.next().unwrap().unwrap();
        assert_eq!(
            value["raw_evidence"]["data"],
            STANDARD.encode(harmless_escaped)
        );
        assert!(secrets.issued.carries(b"abc_123"));
        assert!(secrets.issued.carries(b"abc/123"));
        settle(
            lease,
            last_status,
            last_retry.as_deref(),
            last_challenge,
            last_body_failed,
        )
        .unwrap();
        assert!(
            !server
                .requests
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("cookie:")),
            "an issued value must never be retransmitted"
        );
        drop(governor);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unreviewable_or_bounded_cookie_issuance_refuses() {
        // The guard may never screen a subset: a Set-Cookie that cannot be
        // parsed on its own terms refuses the whole response, including a
        // missing '=', an empty name, folded first pairs, ambiguous quoting
        // and non-UTF-8 bytes.
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
            let error = IssuedCookies::default()
                .absorb(&raw)
                .err()
                .expect("an unparseable cookie must refuse");
            assert_eq!(error.code, "invalid_headers", "{header}");
        }
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            reqwest::header::HeaderValue::from_bytes(b"sid=n\x80nutf8; Path=/").unwrap(),
        );
        let error = IssuedCookies::default()
            .absorb(&raw)
            .err()
            .expect("non-UTF-8 cookie material must refuse");
        assert_eq!(error.code, "invalid_headers");
        // The credential history is bounded across the invocation: more
        // than the admitted values or bytes refuses rather than evicting an
        // older secret.
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
        // The byte bound is cumulative: sixteen distinct maximum-size
        // values fill the history exactly, an identical repeat still adds
        // nothing, and a new value is refused rather than evicting an
        // earlier secret. Each value stays under the cookie-value grammar
        // ceiling of 4096 bytes.
        let mut issued = IssuedCookies::default();
        for index in 0..MAX_ISSUED_COOKIE_BYTES / 4096 {
            let mut raw = reqwest::header::HeaderMap::new();
            raw.insert(
                reqwest::header::SET_COOKIE,
                format!("sid{index}={:04096}", index).parse().unwrap(),
            );
            issued.absorb(&raw).unwrap();
        }
        assert_eq!(issued.values.len(), MAX_ISSUED_COOKIE_BYTES / 4096);
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            format!("sid0={:04096}", 0).parse().unwrap(),
        );
        issued
            .absorb(&raw)
            .expect("an already-retained value must not hit the bound");
        assert_eq!(issued.values.len(), MAX_ISSUED_COOKIE_BYTES / 4096);
        let mut raw = reqwest::header::HeaderMap::new();
        raw.insert(
            reqwest::header::SET_COOKIE,
            "sid=new-value".parse().unwrap(),
        );
        let error = issued
            .absorb(&raw)
            .err()
            .expect("the byte bound must refuse");
        assert_eq!(error.code, "invalid_headers");
        assert!(
            issued.carries(format!("marker {:04096}", 1).as_bytes()),
            "bound exhaustion must not evict old values"
        );
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
        let mut issued = IssuedCookies::default();
        issued.absorb(&raw).unwrap();
        assert_eq!(issued.values.len(), 1);
        assert!(issued.carries(br#"{"value":"kept-private-value"}"#));
        assert!(!issued.carries(br#"{"value":"ordinary"}"#));
    }

    #[test]
    fn aes_known_block_and_padding() {
        let key = [0u8; 16];
        let encrypted = aes(&[0u8; 16], &key, true).unwrap();
        assert_eq!(
            &encrypted[..16],
            &[
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
                0x2b, 0x2e
            ]
        );
        assert_eq!(&*aes(&encrypted, &key, false).unwrap(), &vec![0u8; 16]);
    }
    #[test]
    fn quoted_ciphertext_preserves_the_decrypted_source_data() {
        let key = [0u8; 16];
        let data = json!({"name":"synthetic course","members":[17,23],"enabled":true});
        let plain = serde_json::to_vec(&json!({"status":"0","data":data})).unwrap();
        let cipher = STANDARD.encode(aes(&plain, &key, true).unwrap().as_slice());
        let wire = format!(" \n{}\r\n", serde_json::to_string(&cipher).unwrap());
        assert_eq!(
            decode_response(wire.as_bytes(), Some("application/json"), &key),
            json!({"result":"success","data":data})
        );
    }

    #[test]
    fn quoted_ciphertext_failure_retains_the_original_wire_bytes() {
        let wire = b" \n\"ordinary invalid ciphertext\"\r\n";
        let output = decode_response(wire, Some("application/json"), &[0u8; 16]);
        assert_eq!(output["result"], "fallback");
        assert_eq!(
            output["fallback_reason"],
            "base64_aes_json_contract_unrecognized"
        );
        assert_eq!(output["raw_evidence"]["data"], STANDARD.encode(wire));
        assert_eq!(output["raw_evidence"]["byte_length"], wire.len());
        assert_eq!(
            output["raw_evidence"]["sha256"],
            format!("{:x}", Sha256::digest(wire))
        );
    }

    #[test]
    fn quoted_ciphertext_with_sensitive_plaintext_withholds_the_original() {
        let key = [0u8; 16];
        let plain = br#"{"status":"0","data":{"access_token":"synthetic-private-material"}}"#;
        let cipher = STANDARD.encode(aes(plain, &key, true).unwrap().as_slice());
        let wire = serde_json::to_vec(&cipher).unwrap();
        let output = decode_response(&wire, Some("application/json"), &key);
        assert_eq!(output["fallback_reason"], "sensitive_response_withheld");
        assert_eq!(output["raw_evidence"]["data"], Value::Null);
        assert_eq!(
            output["raw_evidence"]["raw_withheld_reason"],
            "credential_echo"
        );
        assert!(!output.to_string().contains("synthetic-private-material"));
    }

    #[test]
    fn status_error() {
        let key = [0u8; 16];
        let wire = STANDARD.encode(
            aes(br#"{"status":"9","errmsg":"synthetic"}"#, &key, true)
                .unwrap()
                .as_slice(),
        );
        assert_eq!(
            decode_response(wire.as_bytes(), Some("text/plain"), &key)["result"],
            "upstream_error"
        );
    }
    #[test]
    fn page_contract() {
        assert!(
            parse_page(
                &json!({"content":[],"totalElements":0,"totalPages":0,"size":20,"number":0})
            )
            .is_ok()
        );
        assert!(parse_page(&json!({"content":[]})).is_err());
    }
    #[test]
    fn unknown_writes_never_offer_confirmation() {
        assert_eq!(
            preview_write(&WriteIntent {
                operation: WriteOperation::Select,
                course_id: "fixture".into(),
                owner_present: true
            })["confirmation_available"],
            false
        );
    }
    #[test]
    fn rsa_contract_and_token_admission() {
        assert_eq!(
            STANDARD.decode(rsa(b"fixture").unwrap()).unwrap().len(),
            128
        );
        assert!(auth_token("http://bykc.buaa.edu.cn/?token=x").is_err());
        assert_eq!(
            auth_token("https://bykc.buaa.edu.cn/system/course-select?token=a%2Bb")
                .unwrap()
                .as_str(),
            "a+b"
        );
    }
    #[test]
    fn offline_entry_and_write_blocked() {
        assert_eq!(
            run(r#"{"operation":"profile"}"#, false).unwrap()["result"],
            "blocked"
        );
        assert_eq!(
            run(r#"{"operation":"preview_write"}"#, true).unwrap()["confirmation_available"],
            false
        );
        assert_eq!(
            run(r#"["profile",{"auth_token":"opaque123"}]"#, false).unwrap()["reason"],
            "invalid_input"
        );
        assert_eq!(
            run(r#"[{"auth_token":"opaque123"}]"#, false).unwrap()["reason"],
            "invalid_input"
        );
    }
    #[test]
    fn positional_queries_are_refused() {
        assert_eq!(
            run(
                r#"{"operation":"semester_courses","payload":{"query":[1,20]}}"#,
                false
            )
            .unwrap()["reason"],
            "invalid_input"
        );
        assert_eq!(
            run(
                r#"{"operation":"chosen","payload":{"query":["2026-01-01","2026-01-02"]}}"#,
                false
            )
            .unwrap()["reason"],
            "invalid_input"
        );
        assert!(serde_json::from_str::<PageRequest>(r#"[1,20]"#).is_err());
        assert!(serde_json::from_str::<DateRequest>(r#"["a","b"]"#).is_err());
    }
    #[test]
    fn unsafe_raw_evidence_is_withheld() {
        let challenge = decode_response(
            br#"<form><input name="captcha" value="unsafe"></form>"#,
            Some("text/html"),
            &[0u8; 16],
        );
        assert_eq!(challenge["raw_evidence"]["data"], Value::Null);
        assert_eq!(
            challenge["raw_evidence"]["raw_withheld_reason"],
            "challenge_detected"
        );
        assert!(!challenge.to_string().contains("unsafe"));
        let partial = raw_evidence(b"ordinary prefix", Some("text/plain"), false);
        assert_eq!(partial["data"], Value::Null);
        assert_eq!(partial["raw_withheld_reason"], "response_safety_unreviewed");
        let safe = raw_evidence(b"ordinary text", Some("text/plain"), true);
        assert_eq!(safe["data"], "b3JkaW5hcnkgdGV4dA==");
    }
    #[test]
    fn secret_echoes_never_leave_through_fallback() {
        let secret = "private\"token";
        assert!(response_contains_secret(
            br#"{"echo":"private\"token"}"#,
            None,
            secret
        ));
        assert!(response_contains_secret(
            b"safe",
            Some("text/plain; private\"token"),
            secret
        ));
        assert!(value_contains_secret(&json!({"nested":[secret]}), secret));
        let out = withheld_fallback(secret.as_bytes(), Some("text/plain"));
        assert!(!out.to_string().contains("private"));
        assert_eq!(out["raw_evidence"]["data"], Value::Null);
        let out = fallback(
            b"new access_token=private-material",
            Some("text/plain"),
            "unrecognized",
        );
        assert_eq!(out["raw_evidence"]["data"], Value::Null);
        assert!(!out.to_string().contains("private-material"));
    }
    #[test]
    fn cas_exchange_blocks_before_admission() {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "boya-auth-preflight-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let client = BoyaClient {
            http: reqwest::blocking::Client::builder()
                .retry(reqwest::retry::never())
                .build()
                .unwrap(),
            governor: Governor::isolated_for_test(&path).unwrap(),
        };
        assert_eq!(
            client.login("private-cookie", false).unwrap_err().code,
            "unsupported"
        );
        assert!(!client.governor.status().unwrap().safety_latched);
        drop(client);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn decoded_response_and_original_input_are_protected() {
        let key = [0u8; 16];
        let wire = STANDARD.encode(
            aes(
                br#"{"status":"0","data":{"\u0061ccess_token":"fresh-material"}}"#,
                &key,
                true,
            )
            .unwrap()
            .as_slice(),
        );
        let out = decode_response(wire.as_bytes(), Some("text/plain"), &key);
        assert_ne!(out["result"], "success");
        assert!(!out.to_string().contains("fresh-material"));
        assert_ne!(
            decode_response(wire.as_bytes(), Some("application/xhtml+xml"), &key)["result"],
            "success"
        );
        assert!(response_contains_secret(
            br#"{"echo":"\u006fpaque123"}"#,
            Some("application/json"),
            "opaque123"
        ));
        let input: RunInput =
            serde_json::from_str(r#"{"operation":"profile","payload":{"auth_token":"opaque123"}}"#)
                .unwrap();
        let token = input.payload.unwrap().auth_token.unwrap();
        let _: &Zeroizing<String> = &token.0;
        assert_eq!(
            run(
                r#"{"operation":"profile","payload":{"auth_token":"opaque123"}}"#,
                false
            )
            .unwrap()["result"],
            "blocked"
        );
        assert!(
            serde_json::from_slice::<PrivateValue>(br#"{"first":"private","first":"duplicate"}"#)
                .is_err()
        );
    }
    #[test]
    fn invalid_credential_never_consumes_a_request() {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "boya-header-preflight-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let client = BoyaClient {
            http: reqwest::blocking::Client::builder().build().unwrap(),
            governor: Governor::isolated_for_test(&path).unwrap(),
        };
        assert_eq!(
            client
                .read("bad\nheader", &ReadRequest::Profile)
                .unwrap_err()
                .code,
            "invalid_input"
        );
        assert!(!client.governor.status().unwrap().safety_latched);
        drop(client);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn nested_shape_and_encoded_echo_contracts() {
        assert!(response_contains_secret(
            b"echo=abc%2B123",
            Some("text/plain"),
            "abc+123"
        ));
        assert!(response_contains_secret(
            b"echo=abc%2b123",
            Some("text/plain"),
            "abc+123"
        ));
        assert_eq!(
            evidence(
                b"safe",
                Some("application/json; proof=freshopaque123"),
                Some("withheld")
            )["content_type"],
            "application/json"
        );
        assert_eq!(
            run(
                r#"{"operation":"profile","payload":["opaque123",null,null]}"#,
                true
            )
            .unwrap()["reason"],
            "invalid_input"
        );
        assert!(
            serde_json::from_str::<PageRequest>(" \n {\"pageNumber\":1,\"pageSize\":20} \t")
                .is_ok()
        );
        assert!(serde_json::from_str::<DateRequest>(r#"{"startDate":"a","endDate":"b"}"#).is_ok());
    }
    #[test]
    fn composed_encoding_and_ambiguous_headers_refuse() {
        let encoded = b"%61%63%63%65%73%73%5F%74%6F%6B%65%6E=opaqueABC123";
        assert_eq!(
            raw_evidence(encoded, Some("application/x-www-form-urlencoded"), true)["data"],
            Value::Null
        );
        let key = [0u8; 16];
        let wire = STANDARD.encode(
            aes(
                br#"{"status":"0","data":{"echo":"abc%2B\u0031\u0032\u0033"}}"#,
                &key,
                true,
            )
            .unwrap()
            .as_slice(),
        );
        let decoded = PrivateValue(decode_response(wire.as_bytes(), Some("text/plain"), &key));
        assert!(value_contains_secret(&decoded, "abc+123"));
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "content-type",
            reqwest::header::HeaderValue::from_static("text/plain"),
        );
        headers.append(
            "content-type",
            reqwest::header::HeaderValue::from_static("text/html"),
        );
        let mime = response_content_type(&headers);
        assert!(mime.is_none());
        assert_ne!(
            crate::html::assess_challenge_body(b"<input name=captcha>", mime.as_deref(), true),
            crate::html::ChallengeAssessment::Clear
        );
    }

    fn course_page(
        number: u64,
        total_elements: u64,
        total_pages: u64,
        size: u64,
        ids: impl IntoIterator<Item = u64>,
    ) -> Value {
        let content: Vec<Value> = ids.into_iter().map(|id| json!({"id":id})).collect();
        json!({"result":"success","data":{"content":content,"totalElements":total_elements,"totalPages":total_pages,"size":size,"number":number}})
    }

    fn traverse(request: &PageRequest, pages: &[Value]) -> Value {
        let mut traversal = CourseTraversal::new(request);
        for page in pages {
            if matches!(traversal.advance(page), Step::Done) {
                break;
            }
        }
        traversal.envelope()
    }

    #[test]
    fn course_pages_stop_at_the_source_declared_terminal() {
        let request = PageRequest {
            page_number: 0,
            page_size: 20,
            max_pages: 5,
        };
        let output = traverse(
            &request,
            &[
                course_page(0, 57, 3, 20, 0..20),
                course_page(1, 57, 3, 20, 20..40),
                course_page(2, 57, 3, 20, 40..57),
            ],
        );
        assert_eq!(output["result"], "success");
        assert_eq!(output["complete"], true);
        assert!(output["incomplete_reason"].is_null());
        assert_eq!(output["entry_count"], 57);
        assert_eq!(output["entries"].as_array().unwrap().len(), 57);
        assert_eq!(output["pagination"]["pages_fetched"], 3);
        assert_eq!(output["pagination"]["declared_total_elements"], 57);
        assert_eq!(output["pagination"]["declared_total_pages"], 3);
        assert_eq!(output["pagination"]["pages"][2]["count"], 17);
        assert!(output["page_failure"].is_null());
    }

    #[test]
    fn course_pages_stop_at_the_caller_bound_without_claiming_completeness() {
        let request = PageRequest {
            page_number: 0,
            page_size: 20,
            max_pages: 1,
        };
        let output = traverse(
            &request,
            &[
                course_page(0, 57, 3, 20, 0..20),
                course_page(1, 57, 3, 20, 20..40),
            ],
        );
        assert_eq!(output["result"], "partial");
        assert_eq!(output["complete"], false);
        assert_eq!(output["incomplete_reason"], "page_bound_reached");
        assert_eq!(output["entry_count"], 20);
        assert_eq!(output["pagination"]["pages_fetched"], 1);
        assert_eq!(output["pagination"]["max_pages"], 1);
    }

    #[test]
    fn course_pages_refuse_changed_totals_and_short_pages() {
        let request = PageRequest {
            page_number: 0,
            page_size: 20,
            max_pages: 3,
        };
        let changed = traverse(
            &request,
            &[
                course_page(0, 57, 3, 20, 0..20),
                course_page(1, 40, 2, 20, 20..40),
            ],
        );
        assert_eq!(changed["complete"], false);
        assert_eq!(changed["incomplete_reason"], "pagination_changed");
        assert_eq!(changed["entry_count"], 20);
        assert_eq!(changed["page_failure"], course_page(1, 40, 2, 20, 20..40));
        let short = traverse(&request, &[course_page(0, 57, 3, 20, 0..19)]);
        assert_eq!(short["incomplete_reason"], "pagination_inconsistent");
        assert_eq!(short["entry_count"], 0);
        let exhausted = traverse(&request, &[course_page(0, 40, 1, 20, 0..20)]);
        assert_eq!(exhausted["incomplete_reason"], "pagination_inconsistent");
        assert_eq!(exhausted["entry_count"], 20);
    }

    #[test]
    fn course_pages_refuse_renumbered_duplicate_and_unidentified_records() {
        let request = PageRequest {
            page_number: 0,
            page_size: 20,
            max_pages: 2,
        };
        let renumbered = traverse(
            &request,
            &[
                course_page(0, 40, 2, 20, 0..20),
                course_page(5, 40, 2, 20, 20..40),
            ],
        );
        assert_eq!(renumbered["incomplete_reason"], "pagination_page_mismatch");
        assert_eq!(renumbered["entry_count"], 20);
        let duplicate = traverse(
            &request,
            &[
                course_page(0, 40, 2, 20, 0..20),
                course_page(1, 40, 2, 20, 19..39),
            ],
        );
        assert_eq!(duplicate["incomplete_reason"], "duplicate_course_id");
        assert_eq!(duplicate["entry_count"], 20);
        let unidentified = json!({"result":"success","data":{"content":[{"name":"synthetic"}],"totalElements":1,"totalPages":1,"size":20,"number":0}});
        let output = traverse(&request, &[unidentified]);
        assert_eq!(output["incomplete_reason"], "entry_id_unconfirmed");
        assert_eq!(output["entry_count"], 0);
    }

    #[test]
    fn course_pages_follow_the_source_declared_page_base() {
        // The caller numbers the first page 1 while the source answers with 0.
        // That mapping is declared by the first response and then required, so
        // the next request is the source's declared page 1 under request 2.
        let request = PageRequest {
            page_number: 1,
            page_size: 20,
            max_pages: 2,
        };
        let output = traverse(
            &request,
            &[
                course_page(0, 40, 2, 20, 0..20),
                course_page(1, 40, 2, 20, 20..40),
            ],
        );
        assert_eq!(output["result"], "success");
        assert_eq!(output["complete"], true);
        assert_eq!(output["entry_count"], 40);
        assert_eq!(output["pagination"]["pages_fetched"], 2);
        assert_eq!(output["pagination"]["start_page"], 1);
    }

    #[test]
    fn course_pages_keep_declared_and_degraded_pages_verbatim() {
        let request = PageRequest {
            page_number: 0,
            page_size: 20,
            max_pages: 2,
        };
        let empty = traverse(&request, &[course_page(0, 0, 0, 20, std::iter::empty())]);
        assert_eq!(empty["complete"], true);
        assert_eq!(empty["entry_count"], 0);
        let degraded = json!({"result":"fallback","fallback_reason":"invalid_pagination_contract","raw_evidence":{"sha256":"synthetic"}});
        let output = traverse(&request, &[degraded.clone()]);
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["complete"], false);
        assert_eq!(output["incomplete_reason"], "source_page_not_success");
        assert_eq!(output["page_failure"], degraded);
        assert_eq!(output["entry_count"], 0);
    }

    #[test]
    fn chosen_whole_list_reports_completeness_without_page_counts() {
        let admitted = json!({"result":"success","data":{"courseList":[{"id":1},{"id":2}]}});
        let output = whole_list(admitted);
        assert_eq!(output["result"], "success");
        assert_eq!(output["list_contract"], "whole_list");
        assert_eq!(output["complete"], true);
        assert!(output["incomplete_reason"].is_null());
        assert_eq!(output["entry_count"], 2);
        assert!(output["pagination"].is_null());
        let duplicate =
            whole_list(json!({"result":"success","data":{"courseList":[{"id":1},{"id":1}]}}));
        assert_eq!(duplicate["result"], "partial");
        assert_eq!(duplicate["incomplete_reason"], "duplicate_course_id");
        assert_eq!(duplicate["entry_count"], 1);
        let unrecognized = whole_list(json!({"result":"success","data":{"other":[]}}));
        assert_eq!(
            unrecognized["incomplete_reason"],
            "list_contract_unrecognized"
        );
        assert!(unrecognized["entries"].is_null());
        assert_eq!(unrecognized["data"], json!({"other":[]}));
        let degraded = whole_list(json!({"result":"fallback","fallback_reason":"synthetic"}));
        assert_eq!(degraded["result"], "fallback");
        assert_eq!(degraded["fallback_reason"], "synthetic");
        assert_eq!(degraded["complete"], false);
        assert_eq!(degraded["incomplete_reason"], "source_page_not_success");
    }

    #[test]
    fn contradictory_page_extents_never_claim_completeness() {
        let request = PageRequest {
            page_number: 0,
            page_size: 2,
            max_pages: 3,
        };
        for page in [
            course_page(0, 2, 0, 2, [1, 2]),
            course_page(0, 2, 3, 2, [1, 2]),
            course_page(0, 0, 3, 2, []),
            course_page(3, 2, 1, 2, [1, 2]),
        ] {
            let output = traverse(&request, &[page.clone()]);
            assert_eq!(output["complete"], false);
            assert_eq!(output["incomplete_reason"], "pagination_inconsistent");
            assert_eq!(output["page_failure"], page);
        }
    }

    #[test]
    fn later_rejection_and_whole_list_identity_failure_preserve_admitted_evidence() {
        let request = PageRequest {
            page_number: 0,
            page_size: 2,
            max_pages: 2,
        };
        let rejected = json!({"result":"page_rejected","error":"http_error","http_status":500});
        let output = traverse(
            &request,
            &[course_page(0, 4, 2, 2, [1, 2]), rejected.clone()],
        );
        assert_eq!(output["complete"], false);
        assert_eq!(output["entries"], json!([{"id":1},{"id":2}]));
        assert_eq!(output["page_failure"], rejected);

        for source in [
            json!({"result":"success","data":{"courseList":[{"id":1},{"id":1},{"id":2}]}}),
            json!({"result":"success","data":{"courseList":[{"name":"unidentified"},{"id":2}]}}),
        ] {
            let output = whole_list(source.clone());
            assert_eq!(output["complete"], false);
            assert_eq!(output["page_failure"], source);
        }
    }

    #[test]
    fn max_pages_is_local_bounded_and_defaulted() {
        let parsed: PageRequest =
            serde_json::from_str(r#"{"pageNumber":1,"pageSize":20,"maxPages":3}"#).unwrap();
        assert_eq!(parsed.max_pages, 3);
        let (_, data) = payload(&ReadRequest::Courses(parsed)).unwrap();
        assert_eq!(data, json!({"pageNumber":1,"pageSize":20}));
        let default: PageRequest =
            serde_json::from_str(r#"{"pageNumber":0,"pageSize":20}"#).unwrap();
        assert_eq!(default.max_pages, 1);
        for max_pages in [0, MAX_TRAVERSAL_PAGES + 1] {
            let request = ReadRequest::Courses(PageRequest {
                page_number: 0,
                page_size: 20,
                max_pages,
            });
            assert_eq!(payload(&request).unwrap_err().code, "invalid_input");
        }
        assert!(serde_json::from_str::<PageRequest>(r#"[1,20,3]"#).is_err());
        assert!(
            serde_json::from_str::<PageRequest>(
                r#"{"pageNumber":1,"pageSize":20,"maxPages":3,"extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn session_input_refuses_a_positional_root() {
        let positional =
            r#"["private","user","private","LOGIN user boya",{"operation":"profile"}]"#;
        assert!(serde_json::from_str::<SessionInput>(positional).is_err());
        let object = r#"{"authorized":false,"username":"user","password":"private","intent":"LOGIN user boya","read":{"operation":"profile"}}"#;
        let parsed = serde_json::from_str::<SessionInput>(object).unwrap();
        assert!(!parsed.authorized);
        assert_eq!(parsed.intent, "LOGIN user boya");
    }

    #[test]
    fn schema_declares_the_implemented_offline_state_and_pagination() {
        let schema = schema();
        assert_eq!(schema["state"], "partial-offline");
        assert!(
            schema["state_detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("bounded pagination"))
        );
        assert_eq!(
            schema["output"]["properties"]["result"]["enum"][1],
            "partial"
        );
        assert_eq!(
            schema["output"]["properties"]["complete"]["type"],
            "boolean"
        );
        assert_eq!(
            schema["pagination"]["request"]["maxPages"]["maximum"],
            MAX_TRAVERSAL_PAGES
        );
        assert_eq!(
            schema["pagination"]["whole_list"]["applies_to"][0],
            "chosen"
        );
        assert!(
            schema["session"]["description"]
                .as_str()
                .is_some_and(|text| text.contains("maxPages"))
        );
    }
}

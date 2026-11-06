//! AnyShare efast contracts. No implicit login, refresh, retry or mutation.
//! OAuth password encryption is deliberately unavailable without an admitted
//! platform public key and padding contract; a client identifier is not a key.
//! Blocked without an admitted contract, and never implied by any output:
//! OAuth authorization state, every token-exchange path, the `/dir/list`
//! attribute/order contract, transfers, and every mutation commit or
//! postcondition check.
use crate::governor::{Governor, Outcome};
use crate::net::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use url::Url;
use zeroize::{Zeroize, Zeroizing};
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
fn private_value(value: &Value, secret: Option<&str>) -> bool {
    let sensitive = |text: &str| match secret {
        Some(secret) => crate::net::carries_secret(text.as_bytes(), secret),
        None => sensitive_raw(text.as_bytes()),
    };
    match value {
        Value::String(text) => sensitive(text),
        Value::Array(values) => values.iter().any(|value| private_value(value, secret)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| sensitive(key) || private_value(value, secret)),
        Value::Number(_) | Value::Bool(_) | Value::Null => secret.is_some_and(|secret| {
            crate::net::json_scalar_matches(value, |bytes| {
                crate::net::carries_secret(bytes, secret)
            })
        }),
    }
}
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}
fn object<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    struct Visitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, access: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(access))
        }
    }
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

const AUTHORITY_HOST: &str = "bhpan.buaa.edu.cn";
const MAX_BODY: u64 = 32 * 1024 * 1024;
/// Bounds shared by tree traversal and client-snapshot pagination.
const MAX_SNAPSHOT_ENTRIES: usize = 100_000;
const MAX_CURSOR_LEN: usize = 2048;
const CURSOR_VERSION: u8 = 1;
fn err(code: &'static str) -> Error {
    Error::new(code, "drive contract refused; no automatic retry")
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn rejection_code(body: &[u8]) -> Option<i64> {
    struct Facts<'a>(&'a std::cell::Cell<Option<i64>>);
    impl<'de> serde::de::Visitor<'de> for Facts<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("response object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut access: A) -> Result<(), A::Error> {
            while let Some(key) = access.next_key::<String>()? {
                let key = Zeroizing::new(key);
                if key.as_str() == "code" {
                    let value = access.next_value::<PrivateValue>()?;
                    let code = value.as_i64().or_else(|| value.as_str()?.parse().ok());
                    if matches!(code, Some(401001001 | 401001003))
                        && (self.0.get() != Some(401001003))
                    {
                        self.0.set(code);
                    }
                } else {
                    access.next_value::<serde::de::IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }
    let code = std::cell::Cell::new(None);
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let _ = serde::Deserializer::deserialize_map(&mut deserializer, Facts(&code));
    code.get()
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
/// Decode every JSON string literal in `bytes` into one contiguous review
/// buffer. Duplicate members and a non-object shape do not stop this scan:
/// literals are located syntactically, so a body serde refused to normalize
/// is still screened. `None` means some quoted run or escape could not be
/// decoded (a bad `\u` digit, a lone surrogate, an unknown escape or an
/// unterminated literal); the caller must treat the escaped material as
/// unreviewable rather than release bytes it could not finish reading.
fn decoded_string_literals(bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let hex4 = |at: &[u8]| -> Option<u32> {
        let mut value: u32 = 0;
        for byte in at {
            value = value << 4 | (*byte as char).to_digit(16)?;
        }
        Some(value)
    };
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        index += 1;
        loop {
            match *bytes.get(index)? {
                b'"' => {
                    index += 1;
                    break;
                }
                b'\\' => {
                    match *bytes.get(index + 1)? {
                        escaped @ (b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            out.push(match escaped {
                                b'b' => 0x08,
                                b'f' => 0x0C,
                                b'n' => b'\n',
                                b'r' => b'\r',
                                b't' => b'\t',
                                plain => plain,
                            });
                            index += 2;
                        }
                        b'u' => {
                            let first = hex4(bytes.get(index + 2..index + 6)?)?;
                            index += 6;
                            let scalar = if (0xD800..0xDC00).contains(&first) {
                                if bytes.get(index) != Some(&b'\\')
                                    || bytes.get(index + 1) != Some(&b'u')
                                {
                                    return None;
                                }
                                let low = hex4(bytes.get(index + 2..index + 6)?)?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return None;
                                }
                                index += 6;
                                0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&first) {
                                return None;
                            } else {
                                first
                            };
                            out.extend_from_slice(
                                char::from_u32(scalar)?
                                    .encode_utf8(&mut [0; 4])
                                    .as_bytes(),
                            );
                        }
                        _ => return None,
                    }
                }
                byte => {
                    out.push(byte);
                    index += 1;
                }
            }
        }
        // One NUL separates decoded literals so a credential can never be
        // assembled across two adjacent string boundaries.
        out.push(0);
    }
    Some(out)
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
fn response_contains_secret(bytes: &[u8], content_type: Option<&str>, secret: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    let contains = |candidate: &[u8]| crate::net::carries_secret(candidate, secret);
    contains(bytes)
        || content_type.is_some_and(|value| contains(value.as_bytes()))
        || match decoded_string_literals(bytes) {
            // A credential escaped inside a duplicate-member or otherwise
            // unparseable body still decodes to that credential; escaped
            // material that cannot be fully decoded is unreviewable.
            None => true,
            Some(literals) => contains(&literals),
        }
        || serde_json::from_slice::<PrivateValue>(bytes)
            .ok()
            .is_some_and(|value| private_value(&value, Some(secret)))
}

/// Authorization-URL production is blocked: the historical fixed state is not
/// a private single-consumption binding, and token exchange has no sink.
pub fn auth_url(_host: &str) -> Result<Url, Error> {
    Err(err("oauth_authorization_state_unsafe"))
}
fn base(host: &str) -> Result<Url, Error> {
    if host != AUTHORITY_HOST {
        return Err(err("authority_host_unsupported"));
    }
    let url = Url::parse(&format!("https://{host}:443/")).map_err(|_| err("invalid_host"))?;
    if url.host_str() != Some(host)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(err("invalid_host"));
    }
    Ok(url)
}

/// Secret-bearing values deliberately have no Debug or Serialize implementation.
pub struct LoginChallenge {
    csrf: Zeroizing<String>,
    challenge: Zeroizing<String>,
}
impl LoginChallenge {
    pub fn parse(html: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(html).map_err(|_| err("login_html_invalid"))?;
        fn field(text: &str, key: &str) -> Result<Zeroizing<String>, Error> {
            let needle = format!("\"{key}\"");
            let mut matches = text.match_indices(&needle);
            let (at, _) = matches.next().ok_or_else(|| err("login_field_missing"))?;
            if matches.next().is_some() {
                return Err(err("login_field_ambiguous"));
            }
            let tail = text[at + needle.len()..]
                .trim_start()
                .strip_prefix(':')
                .ok_or_else(|| err("login_field_invalid"))?
                .trim_start();
            let mut stream = serde_json::Deserializer::from_str(tail).into_iter::<String>();
            let result = Zeroizing::new(
                stream
                    .next()
                    .ok_or_else(|| err("login_field_invalid"))?
                    .map_err(|_| err("login_field_invalid"))?,
            );
            if result.is_empty() {
                return Err(err("login_field_invalid"));
            }
            Ok(result)
        }
        Ok(Self {
            csrf: field(text, "csrftoken")?,
            challenge: field(text, "challenge")?,
        })
    }
    /// Expose neither nonce in receipts; only readiness is public.
    pub fn ready(&self) -> bool {
        !self.csrf.is_empty() && !self.challenge.is_empty()
    }
}

/// No callback code can be admitted without a private, session-bound state
/// and a proven private exchange sink. This avoids a misleading public helper.
pub fn authorization_code(_location: &str) -> Result<Zeroizing<String>, Error> {
    Err(err("oauth_callback_state_unsafe"))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub docid: String,
    pub name: String,
    pub rev: String,
    pub size: i64,
    #[serde(default)]
    pub modified: Value,
}
impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            docid: String,
            name: String,
            rev: String,
            size: i64,
            #[serde(default)]
            modified: Value,
        }
        let fields: Fields = object(deserializer)?;
        Ok(Self {
            docid: fields.docid,
            name: fields.name,
            rev: fields.rev,
            size: fields.size,
            modified: fields.modified,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub raw_base64: String,
    pub content_type: Option<String>,
    pub byte_length: usize,
    pub sha256: String,
    pub fallback_reason: String,
    #[serde(default)]
    pub raw_withheld: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_withheld_reason: Option<String>,
}
impl Evidence {
    pub fn new(bytes: &[u8], content_type: Option<&str>, reason: &str) -> Self {
        let withheld = match crate::html::assess_challenge_body(bytes, content_type, true) {
            crate::html::ChallengeAssessment::Clear => None,
            crate::html::ChallengeAssessment::Detected => Some("challenge_detected"),
            crate::html::ChallengeAssessment::Unreviewed => Some("response_safety_unreviewed"),
        };
        let withheld = if sensitive_raw(bytes)
            || match decoded_string_literals(bytes) {
                // Escaped literal material that cannot be decoded is
                // unreviewable, and decoded literals are screened for the
                // same markers as the raw body before bytes are released.
                None => true,
                Some(literals) => sensitive_raw(&literals),
            }
            || serde_json::from_slice::<PrivateValue>(bytes)
                .ok()
                .is_some_and(|value| private_value(&value, None))
        {
            Some("sensitive_response_material")
        } else {
            withheld
        };
        Self {
            raw_base64: if withheld.is_none() {
                STANDARD.encode(bytes)
            } else {
                String::new()
            },
            content_type: safe_mime(content_type).map(str::to_owned),
            byte_length: bytes.len(),
            sha256: digest(bytes),
            fallback_reason: reason.into(),
            raw_withheld: withheld.is_some(),
            raw_withheld_reason: withheld.map(str::to_owned),
        }
    }
}
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Listing {
    Structured { entries: Vec<Entry> },
    Degraded { evidence: Evidence },
}
pub fn parse_listing(bytes: &[u8], content_type: Option<&str>) -> Listing {
    if crate::html::assess_challenge_body(bytes, content_type, true)
        != crate::html::ChallengeAssessment::Clear
        || serde_json::from_slice::<PrivateValue>(bytes)
            .ok()
            .is_some_and(|value| private_value(&value, None))
    {
        return Listing::Degraded {
            evidence: Evidence::new(bytes, content_type, "response_not_admitted"),
        };
    }
    fn parse(bytes: &[u8]) -> Option<Vec<Entry>> {
        let value: PrivateValue = serde_json::from_slice(bytes).ok()?;
        let mut result = Vec::new();
        let mut ids = BTreeSet::new();
        for (key, directory) in [("dirs", true), ("files", false)] {
            for item in value.get(key)?.as_array()? {
                let entry = Entry {
                    docid: item.get("docid")?.as_str()?.into(),
                    name: item.get("name")?.as_str()?.into(),
                    rev: item.get("rev")?.as_str()?.into(),
                    size: item.get("size")?.as_i64()?,
                    modified: item.get("modified").cloned().unwrap_or(Value::Null),
                };
                if entry.docid.is_empty()
                    || entry.name.is_empty()
                    || (directory != (entry.size == -1))
                    || entry.size < -1
                    || !ids.insert(entry.docid.clone())
                {
                    return None;
                }
                result.push(entry);
            }
        }
        Some(result)
    }
    match parse(bytes) {
        Some(entries) => Listing::Structured { entries },
        None => Listing::Degraded {
            evidence: Evidence::new(bytes, content_type, "unrecognized_dir_list"),
        },
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    binding: String,
    offset: usize,
}
/// One page of a client-supplied complete snapshot. `complete` is the explicit
/// terminal fact: it is true only when this page reached the end of the bound
/// snapshot, and exactly then `next_cursor` is absent.
#[derive(Debug, Serialize)]
pub struct Page {
    pub entries: Vec<Entry>,
    pub offset: usize,
    pub delivered: usize,
    pub snapshot_entries: usize,
    pub complete: bool,
    pub next_cursor: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Tree {
    /// `complete` describes the traversal only: every queued directory was read
    /// once and no docid repeated. Per-directory listing pagination is still
    /// unconfirmed, so this is never a proven complete inventory.
    Structured {
        entries: Vec<Entry>,
        directories_read: usize,
        complete: bool,
        listing_pagination: &'static str,
    },
    /// Partial traversal. `completed_entries` is never a complete tree, and
    /// `stop_reason` names exactly what stopped the walk.
    Degraded {
        completed_entries: Vec<Entry>,
        directories_read: usize,
        pending_directories: usize,
        complete: bool,
        stop_reason: &'static str,
        response: Value,
    },
}
/// `entries` must be the complete flattened snapshot (including a recursively
/// collected tree when requested); a partial, duplicated or oversized snapshot
/// is refused instead of paginated. Root, traversal mode, ordering, snapshot
/// length and every entry are bound into the cursor, so a different snapshot
/// cannot continue an earlier page chain.
pub fn page(
    root: &str,
    by: &str,
    sort: &str,
    recursive: bool,
    entries: &[Entry],
    limit: usize,
    cursor: Option<&str>,
) -> Result<Page, Error> {
    if root.is_empty()
        || by.is_empty()
        || !(1..=1000).contains(&limit)
        || !matches!(sort, "asc" | "desc")
    {
        return Err(err("invalid_page"));
    }
    if entries.len() > MAX_SNAPSHOT_ENTRIES {
        return Err(err("snapshot_bound_exceeded"));
    }
    // A duplicate docid would deliver one object twice and hide another; such a
    // snapshot is not a complete listing, so no cursor may be issued for it.
    let mut ids = BTreeSet::new();
    for entry in entries {
        if entry.docid.is_empty()
            || entry.name.is_empty()
            || entry.size < -1
            || !ids.insert(entry.docid.as_str())
        {
            return Err(err("snapshot_duplicate_or_invalid_entry"));
        }
    }
    let binding = digest(
        &serde_json::to_vec(&json!({"version": CURSOR_VERSION, "root": root,
        "by": by, "sort": sort, "recursive": recursive, "snapshot_entries": entries.len(),
        "entries": entries}))
        .map_err(|_| err("snapshot_invalid"))?,
    );
    let offset = if let Some(cursor) = cursor {
        if cursor.len() > MAX_CURSOR_LEN {
            return Err(err("invalid_cursor"));
        }
        let decoded = STANDARD.decode(cursor).map_err(|_| err("invalid_cursor"))?;
        let c: Cursor = serde_json::from_slice(&decoded).map_err(|_| err("invalid_cursor"))?;
        // A zero or out-of-range offset is a terminal fact, not a page.
        if c.version != CURSOR_VERSION
            || c.binding != binding
            || c.offset == 0
            || c.offset >= entries.len()
        {
            return Err(err("cursor_snapshot_mismatch"));
        }
        c.offset
    } else {
        0
    };
    let end = offset.saturating_add(limit).min(entries.len());
    let complete = end >= entries.len();
    let next_cursor = if complete {
        None
    } else {
        Some(
            STANDARD.encode(
                serde_json::to_vec(&Cursor {
                    version: CURSOR_VERSION,
                    binding,
                    offset: end,
                })
                .map_err(|_| err("invalid_cursor"))?,
            ),
        )
    };
    Ok(Page {
        entries: entries[offset..end].to_vec(),
        offset,
        delivered: end - offset,
        snapshot_entries: entries.len(),
        complete,
        next_cursor,
    })
}

#[derive(Default, Serialize)]
pub struct IntegrityManifest {
    records: BTreeMap<String, String>,
}
impl<'de> Deserialize<'de> for IntegrityManifest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            records: BTreeMap<String, String>,
        }
        let fields: Fields = object(deserializer)?;
        Ok(Self {
            records: fields.records,
        })
    }
}
impl IntegrityManifest {
    fn key(docid: &str, rev: &str, length: u64) -> String {
        json!([docid, rev, length]).to_string()
    }
    pub fn record(
        &mut self,
        docid: &str,
        rev: &str,
        length: u64,
        bytes: &[u8],
    ) -> Result<String, Error> {
        if docid.is_empty() || rev.is_empty() || bytes.len() as u64 != length {
            return Err(err("length_mismatch"));
        }
        let hash = digest(bytes);
        let key = Self::key(docid, rev, length);
        if self.records.get(&key).is_some_and(|old| old != &hash) {
            return Err(err("integrity_mismatch"));
        }
        self.records.insert(key, hash.clone());
        Ok(hash)
    }
    pub fn verify(&self, docid: &str, rev: &str, length: u64, bytes: &[u8]) -> bool {
        bytes.len() as u64 == length
            && self.records.get(&Self::key(docid, rev, length)) == Some(&digest(bytes))
    }
}

/// In-memory bearer client. Redirects are never automatically followed, so the
/// bearer cannot migrate to an object-storage URL or another origin.
pub struct Client {
    http: reqwest::blocking::Client,
    governor: Governor,
    base: Url,
    token: zeroize::Zeroizing<String>,
    expires: std::time::Instant,
}
enum TokenSend<T> {
    Expired,
    Sent(T),
}
fn send_before_expiry<T>(expires: std::time::Instant, send: impl FnOnce() -> T) -> TokenSend<T> {
    if std::time::Instant::now() >= expires {
        TokenSend::Expired
    } else {
        TokenSend::Sent(send())
    }
}
impl Client {
    /// Collect a bounded, cycle-checked tree before issuing a snapshot cursor.
    /// Every directory request independently acquires and settles the shared lease.
    pub fn tree(
        &self,
        root: &str,
        by: &str,
        sort: &str,
        max_directories: usize,
    ) -> Result<Tree, Error> {
        if root.is_empty()
            || by.is_empty()
            || !matches!(sort, "asc" | "desc")
            || !(1..=1000).contains(&max_directories)
        {
            return Err(err("invalid_tree_bound"));
        }
        let mut pending = vec![root.to_owned()];
        let mut visited = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(docid) = pending.pop() {
            if !visited.insert(docid.clone()) {
                return Err(err("directory_cycle"));
            }
            if visited.len() > max_directories {
                return Err(err("tree_bound_exceeded"));
            }
            let value = self.read(ReadEndpoint::List {
                docid,
                by: by.into(),
                sort: sort.into(),
            })?;
            if value.get("status").and_then(Value::as_str) != Some("structured")
                || value.get("http_status").and_then(Value::as_u64) != Some(200)
            {
                // The walk stops exactly here: earlier directories were fully
                // read, and every directory still queued is still unread.
                return Ok(Tree::Degraded {
                    completed_entries: entries,
                    directories_read: visited.len(),
                    pending_directories: pending.len(),
                    complete: false,
                    stop_reason: "remote_read_degraded",
                    response: value,
                });
            }
            let bytes =
                serde_json::to_vec(&value["value"]).map_err(|_| err("invalid_tree_response"))?;
            let children = match parse_listing(&bytes, Some("application/json")) {
                Listing::Structured { entries } => entries,
                Listing::Degraded { .. } => {
                    return Ok(Tree::Degraded {
                        completed_entries: entries,
                        directories_read: visited.len(),
                        pending_directories: pending.len(),
                        complete: false,
                        stop_reason: "unrecognized_dir_list",
                        response: json!({"status":"degraded","evidence":value["source"],"fallback_reason":"unrecognized_dir_list"}),
                    });
                }
            };
            for entry in children {
                if entry.docid == root || !ids.insert(entry.docid.clone()) {
                    return Err(err("directory_cycle_or_duplicate"));
                }
                if entry.size == -1 {
                    pending.push(entry.docid.clone());
                }
                entries.push(entry);
                if entries.len() > MAX_SNAPSHOT_ENTRIES {
                    return Err(err("tree_entry_bound_exceeded"));
                }
            }
        }
        // Every queued directory was read once and no docid repeated, so the
        // traversal is complete. The per-directory response may itself be
        // paginated upstream, which is not an admitted fact here.
        Ok(Tree::Structured {
            entries,
            directories_read: visited.len(),
            complete: true,
            listing_pagination: "unconfirmed",
        })
    }
    pub fn new(
        host: &str,
        token: Zeroizing<String>,
        remaining_seconds: u64,
    ) -> Result<Self, Error> {
        if host != AUTHORITY_HOST {
            return Err(err("authority_host_unsupported"));
        }
        if token.is_empty()
            || token.chars().any(char::is_control)
            || remaining_seconds == 0
            || remaining_seconds > 3600
        {
            return Err(err("invalid_token"));
        }
        Ok(Self {
            http: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .map_err(|_| err("transport_unavailable"))?,
            governor: Governor::open().map_err(|_| err("governor_unavailable"))?,
            base: base(host)?,
            token,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(remaining_seconds),
        })
    }
    /// Only read contracts are admitted. No guessed mutation or upload semantics.
    pub fn read(&self, endpoint: ReadEndpoint) -> Result<Value, Error> {
        if std::time::Instant::now() >= self.expires {
            return Err(err("token_expired"));
        }
        let (path, body) = endpoint.request()?;
        let url = self
            .base
            .join(&format!("/api/efast/v1{path}"))
            .map_err(|_| err("invalid_endpoint"))?;
        let mut request = if body.is_some() {
            self.http.post(url)
        } else {
            self.http.get(url)
        };
        request = request.bearer_auth(self.token.as_str());
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        let mut lease = crate::net::acquire(&self.governor)?;
        if std::time::Instant::now() >= self.expires {
            lease
                .finish_without_request()
                .map_err(|_| err("governor_settlement"))?;
            return Err(err("token_expired"));
        }
        let request = request.timeout(std::time::Duration::from_secs(60));
        let mut response =
            match lease.start_request(|| send_before_expiry(self.expires, || request.send())) {
                Ok(TokenSend::Expired) => {
                    lease
                        .finish_without_request()
                        .map_err(|_| err("governor_settlement"))?;
                    return Err(err("token_expired"));
                }
                Ok(TokenSend::Sent(Ok(response))) => response,
                Ok(TokenSend::Sent(Err(_))) => {
                    lease
                        .finish(Outcome::NetworkFailure)
                        .map_err(|_| err("governor_settlement"))?;
                    return Err(err("network_failure"));
                }
                Err(crate::governor::FollowupError::Governor(_)) => {
                    return Err(err("governor_settlement"));
                }
            };
        let status = response.status().as_u16();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let ct = response_content_type(response.headers());
        let header_challenge = response
            .headers()
            .iter()
            .any(|(k, v)| crate::net::challenge_header(k.as_str(), v.as_bytes()));
        // A newly issued session cookie is a credential this client never
        // submitted and cannot revoke; its value must never reach the caller.
        let issued_cookie = crate::net::issues_session_cookie(response.headers());
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
            .map_err(|_| err("governor_settlement"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.by_ref().take(MAX_BODY + 1).read_to_end(&mut bytes);
        let incomplete = read.is_err() || bytes.len() as u64 > MAX_BODY;
        let assessment = crate::html::assess_challenge_body(&bytes, ct.as_deref(), !incomplete);
        let challenge =
            header_challenge || assessment == crate::html::ChallengeAssessment::Detected;
        let code = rejection_code(&bytes);
        drop(response);
        // The complete admitted or refused result is computed while the
        // original lease is still held, so no other request is admitted
        // between the response and its admission. The lease settles exactly
        // once, whatever the result.
        let result = (|| {
            if challenge
                || status == 401
                || status == 403
                || code == Some(401001001)
                || code == Some(401001003)
            {
                return Err(err("authentication_or_challenge_refused"));
            }
            if read.is_err() || bytes.len() as u64 > MAX_BODY {
                return Err(err("body_incomplete_or_oversized"));
            }
            if status == 429 || status >= 500 {
                return Err(err("remote_refused"));
            }
            if assessment == crate::html::ChallengeAssessment::Unreviewed {
                return Err(err("response_safety_unreviewed"));
            }
            admit_read_body(
                path,
                status,
                &bytes,
                ct.as_deref(),
                self.token.as_str(),
                issued_cookie,
            )
        })();
        settle_response(lease, status, retry.as_deref(), challenge, incomplete, code)?;
        result
    }
}
fn admit_read_body(
    path: &str,
    status: u16,
    bytes: &[u8],
    content_type: Option<&str>,
    secret: &str,
    issued_cookie: bool,
) -> Result<Value, Error> {
    if response_contains_secret(bytes, content_type, secret) {
        return Err(err("credential_echo_withheld"));
    }
    if issued_cookie {
        return Err(err("session_cookie_refused"));
    }
    // No bearer/token endpoint response can enter raw evidence through this API.
    Ok(read_output(path, status, bytes, content_type))
}
fn settle_response(
    lease: crate::governor::RequestLease<'_>,
    status: u16,
    retry: Option<&str>,
    challenge: bool,
    body_failed: bool,
    code: Option<i64>,
) -> Result<(), Error> {
    // Independently preserve transport facts and application rejection, rather
    // than dropping cooldown/body failure when choosing a credential outcome.
    let outcome = Outcome::Http {
        status,
        retry_after: retry,
        challenge: challenge || matches!(code, Some(401001003 | 401001001)),
        network_failure: body_failed,
    };
    lease
        .finish(outcome)
        .map_err(|_| err("governor_settlement"))
}
fn read_output(path: &str, status: u16, bytes: &[u8], content_type: Option<&str>) -> Value {
    let parsed = serde_json::from_slice::<PrivateValue>(bytes).ok();
    if crate::html::assess_challenge_body(bytes, content_type, true)
        != crate::html::ChallengeAssessment::Clear
        || parsed
            .as_ref()
            .is_some_and(|value| private_value(value, None))
    {
        return json!({"status":"degraded","http_status":status,"network_performed":true,"evidence":Evidence::new(bytes,content_type,"response_not_admitted")});
    }
    let shape_ok = parsed.as_ref().is_some_and(|value| {
        if value.get("code").is_some() {
            return false;
        }
        match path {
            "/dir/list" => matches!(
                parse_listing(bytes, content_type),
                Listing::Structured { .. }
            ),
            p if p.starts_with("/entry-doc-lib?") => value.as_array().is_some_and(|items| {
                items
                    .iter()
                    .all(|v| v.is_object() && v.get("docid").is_some_and(Value::is_string))
            }),
            "/quota/user" => ["quota_used", "quota_allocated", "space_rate"]
                .iter()
                .all(|key| value.get(key).is_some_and(Value::is_number)),
            "/file/convertpath" => value.get("namepath").is_some_and(Value::is_string),
            "/file/getinfobypath" | "/file/metadata" => {
                value.get("docid").is_some_and(Value::is_string)
                    && value.get("name").is_some_and(Value::is_string)
            }
            "/entrydoc2/get" | "/file/revisions" => value.is_array(),
            _ => false,
        }
    });
    if status == 200 && shape_ok {
        json!({"status":"structured","http_status":status,"value":parsed.unwrap(),"network_performed":true,
            "source":Evidence::new(bytes,content_type,"retained_original")})
    } else {
        json!({"status":"degraded","http_status":status,"network_performed":true,
            "evidence":Evidence::new(bytes,content_type,if status != 200 {"http_not_success"} else {"unexpected_application_shape"})})
    }
}
pub enum ReadEndpoint {
    Libraries,
    EntryDocuments,
    Quota,
    InfoByPath(String),
    ConvertPath(String),
    Metadata(String),
    List {
        docid: String,
        by: String,
        sort: String,
    },
    Revisions(String),
}
impl ReadEndpoint {
    fn request(self) -> Result<(&'static str, Option<Value>), Error> {
        Ok(match self {
            Self::Libraries => (
                "/entry-doc-lib?type=user_doc_lib&sort=doc_lib_name&direction=asc",
                None,
            ),
            Self::EntryDocuments => ("/entrydoc2/get", Some(json!({"doctype":1}))),
            Self::Quota => ("/quota/user", None),
            Self::InfoByPath(namepath) => {
                ("/file/getinfobypath", Some(json!({"namepath":namepath})))
            }
            Self::ConvertPath(docid) => ("/file/convertpath", Some(json!({"docid":docid}))),
            Self::Metadata(docid) => ("/file/metadata", Some(json!({"docid":docid}))),
            Self::Revisions(docid) => ("/file/revisions", Some(json!({"docid":docid}))),
            // Neither conflicting candidate attr representation is bound to
            // this deployment. Other read endpoints remain independently usable.
            Self::List { .. } => return Err(err("directory_listing_contract_unconfirmed")),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mutation {
    Upload,
    Move,
    Copy,
    DeleteFile,
    DeleteDirectory,
    Rename,
    CreateDirectory,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub operation: Mutation,
    pub source_docid: Option<String>,
    pub source_rev: Option<String>,
    pub target_path: String,
    pub parent_docid: String,
    pub expected_name: String,
    pub ondup: Option<u8>,
    pub overwrites: Option<bool>,
    pub byte_length: Option<u64>,
    pub local_sha256: Option<String>,
}
impl<'de> Deserialize<'de> for Intent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            operation: Mutation,
            source_docid: Option<String>,
            source_rev: Option<String>,
            target_path: String,
            parent_docid: String,
            expected_name: String,
            ondup: Option<u8>,
            overwrites: Option<bool>,
            byte_length: Option<u64>,
            local_sha256: Option<String>,
        }
        let fields: Fields = object(deserializer)?;
        Ok(Self {
            operation: fields.operation,
            source_docid: fields.source_docid,
            source_rev: fields.source_rev,
            target_path: fields.target_path,
            parent_docid: fields.parent_docid,
            expected_name: fields.expected_name,
            ondup: fields.ondup,
            overwrites: fields.overwrites,
            byte_length: fields.byte_length,
            local_sha256: fields.local_sha256,
        })
    }
}
impl Intent {
    /// Every field is an expectation the caller declares, never a default this
    /// module would invent. A field that cannot apply to the chosen operation
    /// makes the intent ambiguous, so it is refused instead of ignored.
    fn exact(&self) -> Result<(), Error> {
        if self.target_path.is_empty()
            || self.parent_docid.is_empty()
            || self.expected_name.is_empty()
            || self.expected_name.contains('/')
        {
            // Server-selected rename is not an immutable expected-result contract.
            return Err(err("invalid_intent"));
        }
        let source = match (&self.source_docid, &self.source_rev) {
            (Some(docid), Some(rev)) if !docid.is_empty() && !rev.is_empty() => true,
            (None, None) => false,
            _ => return Err(err("intent_source_partial")),
        };
        let creates = matches!(self.operation, Mutation::Upload | Mutation::CreateDirectory);
        if source == creates {
            // A reference operation without an exact docid+revision could act on
            // a different object; a create carrying a source is two intents.
            return Err(err(if creates {
                "intent_source_not_applicable"
            } else {
                "intent_source_required"
            }));
        }
        // Collision policy exists only where a name can already be taken.
        let collides = matches!(
            self.operation,
            Mutation::Upload | Mutation::CreateDirectory | Mutation::Move | Mutation::Copy
        );
        if collides {
            let ondup = self
                .ondup
                .ok_or_else(|| err("ondup_semantics_unconfirmed"))?;
            if !(1..=3).contains(&ondup) || self.overwrites != Some(ondup == 3) || ondup == 2 {
                return Err(err("ambiguous_or_silent_ondup"));
            }
        } else if self.ondup.is_some() || self.overwrites.is_some() {
            return Err(err("collision_policy_not_applicable"));
        }
        if self.operation == Mutation::Upload {
            self.byte_length
                .ok_or_else(|| err("upload_length_required"))?;
            if !self.local_sha256.as_ref().is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }) {
                return Err(err("upload_digest_required"));
            }
        } else if self.byte_length.is_some() || self.local_sha256.is_some() {
            // No local byte stream is declared for this operation, so a length
            // or local digest would be an unverifiable claim.
            return Err(err("transfer_facts_not_applicable"));
        }
        Ok(())
    }
}
/// Immutable by construction: callers can inspect a clone, not mutate the bound intent.
#[derive(Debug)]
pub struct Preview {
    intent: Intent,
    confirmation: String,
}
impl Preview {
    pub fn new(intent: Intent) -> Result<Self, Error> {
        intent.exact()?;
        let confirmation = digest(&serde_json::to_vec(&intent).map_err(|_| err("invalid_intent"))?);
        Ok(Self {
            intent,
            confirmation,
        })
    }
    pub fn inspect(&self) -> Value {
        json!({"intent":self.intent,"confirmation":self.confirmation,
        "confirmation_binds":["operation","source_docid","source_rev","target_path","parent_docid",
            "expected_name","ondup","overwrites","byte_length","local_sha256"],
        "preview_immutable":true,"commit_supported":false,"postconditions":[],
        "blocked_reason":"write_idempotency_and_postcondition_contract_not_admitted"})
    }
    pub fn confirm(&self, confirmation: &str, explicit: bool) -> Result<(), Error> {
        if !explicit || confirmation != self.confirmation {
            return Err(err("explicit_confirmation_required"));
        }
        // A matching, explicitly confirmed preview is still not a remote write:
        // no admitted idempotency key, expected-state check or postcondition
        // verification exists, so no mutation request can be built.
        Err(err(
            "mutation_blocked_missing_idempotency_and_postcondition_contract",
        ))
    }
}

const MAX_KEY_MATERIAL: usize = 64 * 1024;
const MAX_PADDING_LEN: usize = 64;
const MAX_KEY_SOURCE_LEN: usize = 512;

/// Typed token-exchange declaration. Every field is optional at the JSON
/// boundary so an incomplete, ambiguous or inapplicable request is refused with
/// a stable reason instead of being narrowed to one credential path. Neither
/// path is admitted; no supplied material is ever echoed.
struct TokenRequest {
    code: Option<Secret>,
    public_key_pem: Option<String>,
    public_key_source: Option<String>,
    padding: Option<String>,
}
impl TokenRequest {
    fn declared_path(&self) -> Result<&'static str, &'static str> {
        let code = self
            .code
            .as_ref()
            .is_some_and(|code| !code.0.trim().is_empty());
        let key_material = self.public_key_pem.is_some() || self.public_key_source.is_some();
        match (code, key_material) {
            // Two credential paths in one request leave the intended exchange
            // undefined, so nothing may be attempted.
            (true, true) => Err("token_exchange_path_ambiguous"),
            (false, false) => Err("token_exchange_credential_path_missing"),
            // Padding selects a password-encryption contract and cannot apply
            // to an authorization code.
            (true, false) if self.padding.is_some() => Err("token_exchange_path_ambiguous"),
            (true, false) => Ok("authorization_code"),
            (false, true) => {
                let pem = self
                    .public_key_pem
                    .as_deref()
                    .ok_or("public_key_material_incomplete")?;
                let source = self
                    .public_key_source
                    .as_deref()
                    .ok_or("public_key_provenance_missing")?;
                let text = pem.trim();
                if pem.len() > MAX_KEY_MATERIAL
                    || pem.contains('\0')
                    || !text.starts_with("-----BEGIN ")
                    || !text.contains("-----END ")
                    || !text.ends_with("-----")
                {
                    return Err("public_key_pem_invalid");
                }
                if source.is_empty()
                    || source.len() > MAX_KEY_SOURCE_LEN
                    || source.chars().any(char::is_control)
                {
                    return Err("public_key_provenance_invalid");
                }
                let padding = self.padding.as_deref().ok_or("padding_contract_missing")?;
                if padding.is_empty()
                    || padding.len() > MAX_PADDING_LEN
                    || !padding
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    return Err("padding_contract_invalid");
                }
                Ok("password_encryption")
            }
        }
    }
}

enum Input {
    AuthUrl {
        host: String,
    },
    LoginChallenge {
        raw_base64: Secret,
        content_type: Option<String>,
    },
    Token {
        code: Option<Secret>,
        public_key_pem: Option<String>,
        public_key_source: Option<String>,
        padding: Option<String>,
    },
    List {
        host: String,
        access_token: Option<Secret>,
        remaining_seconds: Option<u64>,
        docid: Option<String>,
        by: Option<String>,
        sort: Option<String>,
        raw_base64: Option<Secret>,
        content_type: Option<String>,
    },
    Tree {
        host: String,
        access_token: Secret,
        remaining_seconds: u64,
        root: String,
        by: String,
        sort: String,
        max_directories: usize,
    },
    Page {
        root: String,
        by: String,
        sort: String,
        recursive: bool,
        entries: Vec<Entry>,
        limit: usize,
        cursor: Option<String>,
    },
    Integrity {
        action: IntegrityAction,
        manifest: IntegrityManifest,
        docid: String,
        rev: String,
        length: u64,
        raw_base64: Secret,
    },
    Preview {
        intent: Intent,
    },
}
impl Input {
    fn parse(input: &str) -> Result<Self, serde_json::Error> {
        struct Operation {
            operation: String,
        }
        impl<'de> Deserialize<'de> for Operation {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                struct Probe {
                    operation: String,
                }
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = Operation;
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
                        Probe::deserialize(serde::de::value::MapAccessDeserializer::new(access))
                            .map(|value| Operation {
                                operation: value.operation,
                            })
                    }
                }
                deserializer.deserialize_map(Visitor)
            }
        }
        let operation: Operation = serde_json::from_str(input)?;
        macro_rules! decode{($variant:ident{$($field:ident:$kind:ty),*$(,)?})=>{{
            struct Payload{$($field:$kind),*}
            impl<'de> Deserialize<'de> for Payload{fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->Result<Self,D::Error>{
                #[derive(Deserialize)] #[serde(deny_unknown_fields)] struct Strict{#[serde(rename="operation")]_operation:serde::de::IgnoredAny,$($field:$kind),*}
                struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=Strict;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("JSON object")}
                fn visit_seq<A:serde::de::SeqAccess<'de>>(self,_:A)->Result<Self::Value,A::Error>{Err(serde::de::Error::custom("positional input refused"))}
                fn visit_map<A:serde::de::MapAccess<'de>>(self,access:A)->Result<Self::Value,A::Error>{serde::de::Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(access))}}
                deserializer.deserialize_map(Visitor).map(|value|Self{$($field:value.$field),*})}
            }
            serde_json::from_str::<Payload>(input).map(|value|Self::$variant{$($field:value.$field),*})
        }}}
        match operation.operation.as_str() {
            "auth_url" => decode!(AuthUrl { host: String }),
            "login_challenge" => {
                decode!(LoginChallenge{raw_base64:Secret,content_type:Option<String>})
            }
            "token" => {
                decode!(Token{code:Option<Secret>,public_key_pem:Option<String>,public_key_source:Option<String>,padding:Option<String>})
            }
            "list" => {
                decode!(List{host:String,access_token:Option<Secret>,remaining_seconds:Option<u64>,docid:Option<String>,by:Option<String>,sort:Option<String>,raw_base64:Option<Secret>,content_type:Option<String>})
            }
            "tree" => decode!(Tree {
                host: String,
                access_token: Secret,
                remaining_seconds: u64,
                root: String,
                by: String,
                sort: String,
                max_directories: usize
            }),
            "page" => {
                decode!(Page{root:String,by:String,sort:String,recursive:bool,entries:Vec<Entry>,limit:usize,cursor:Option<String>})
            }
            "integrity" => decode!(Integrity {
                action: IntegrityAction,
                manifest: IntegrityManifest,
                docid: String,
                rev: String,
                length: u64,
                raw_base64: Secret
            }),
            "preview" => decode!(Preview { intent: Intent }),
            _ => Err(<serde_json::Error as serde::de::Error>::custom(
                "unknown operation",
            )),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntegrityAction {
    Record,
    Verify,
}
fn blocked(reason: &str) -> Value {
    json!({"status":"blocked","reason":reason})
}

/// JSON is supplied through stdin by the CLI. Never log the input or Error's
/// source parser diagnostics, which can contain secret values.
pub fn run(input: &str, online: bool) -> Result<Value, Error> {
    if input.len() > 48 * 1024 * 1024 {
        return Ok(blocked("input_too_large"));
    }
    let request: Input = match Input::parse(input) {
        Ok(value) => value,
        Err(_) => return Ok(blocked("invalid_input_or_unknown_field")),
    };
    let execute = || -> Result<Value, Error> {
        Ok(match request {
            Input::AuthUrl { host } => {
                let _ = host;
                blocked("oauth_authorization_state_unsafe")
            }
            Input::LoginChallenge {
                raw_base64,
                content_type,
            } => {
                let bytes = Zeroizing::new(
                    STANDARD
                        .decode(raw_base64.0.as_bytes())
                        .map_err(|_| err("invalid_base64"))?,
                );
                match LoginChallenge::parse(&bytes) {
                    Ok(challenge) => {
                        json!({"status":"structured","challenge_present":challenge.ready(),
                        "csrf_present":true,"secret_values_omitted":true})
                    }
                    // Login HTML contains CSRF/challenge material and must not be a receipt.
                    Err(_) => {
                        json!({"status":"blocked","reason":"login_challenge_parse_failed_secret_html_not_exported",
                        "content_type":safe_mime(content_type.as_deref()),"byte_length":bytes.len(),"sha256":digest(&bytes)})
                    }
                }
            }
            Input::Token {
                code,
                public_key_pem,
                public_key_source,
                padding,
            } => {
                // The declared path is validated and then refused: no exchange
                // request is ever built, and no supplied material is echoed.
                match (TokenRequest {
                    code,
                    public_key_pem,
                    public_key_source,
                    padding,
                })
                .declared_path()
                {
                    Ok("authorization_code") => blocked(
                        "authorization_code_exchange_requires_private_session_bound_state_and_a_non_receipt_sink",
                    ),
                    Ok(_) => blocked(
                        "password_encryption_requires_admitted_platform_public_key_provenance_and_padding_contract",
                    ),
                    Err(reason) => blocked(reason),
                }
            }
            Input::List {
                host,
                access_token,
                remaining_seconds,
                docid,
                by,
                sort,
                raw_base64,
                content_type,
            } => {
                if let Some(raw) = raw_base64 {
                    let bytes = Zeroizing::new(
                        STANDARD
                            .decode(raw.0.as_bytes())
                            .map_err(|_| err("invalid_base64"))?,
                    );
                    let mut value = if access_token.as_ref().is_some_and(|token| {
                        response_contains_secret(&bytes, content_type.as_deref(), token.0.as_str())
                    }) {
                        json!({"status":"degraded","evidence":Evidence{raw_base64:String::new(),content_type:None,byte_length:bytes.len(),sha256:digest(&bytes),fallback_reason:"credential_echo".into(),raw_withheld:true,raw_withheld_reason:Some("credential_echo".into())}})
                    } else {
                        serde_json::to_value(parse_listing(&bytes, content_type.as_deref()))
                            .map_err(|_| err("serialization"))?
                    };
                    value["source"] = json!("operator_supplied");
                    // One supplied response body is not an inventory: the
                    // deployment's pagination and ordering contract is
                    // unconfirmed, so no completeness is claimed.
                    value["completeness"] = json!("single_response_body_pagination_unconfirmed");
                    value["network_performed"] = json!(false);
                    value
                } else if !online {
                    blocked("online_permission_required")
                } else if docid.is_some() {
                    // `/dir/list` attribute and ordering semantics are not
                    // admitted for this deployment, so no listing request is
                    // issued rather than one with a guessed representation.
                    let _ = (by, sort);
                    blocked("directory_listing_contract_unconfirmed")
                } else {
                    // Credential destination is an authentication authority,
                    // unlike offline parsing, which deliberately performs no
                    // request and admits operator evidence by role only.
                    let client = Client::new(
                        &host,
                        access_token.ok_or_else(|| err("token_required"))?.0,
                        remaining_seconds.ok_or_else(|| err("token_expiry_required"))?,
                    )?;
                    client.read(ReadEndpoint::Libraries)?
                }
            }
            Input::Tree {
                host,
                access_token,
                remaining_seconds,
                root,
                by,
                sort,
                max_directories,
            } => {
                if !online {
                    blocked("online_permission_required")
                } else {
                    serde_json::to_value(
                        Client::new(&host, access_token.0, remaining_seconds)?.tree(
                            &root,
                            &by,
                            &sort,
                            max_directories,
                        )?,
                    )
                    .map_err(|_| err("serialization"))?
                }
            }
            // Pagination is a purely local projection of a supplied snapshot;
            // it performs no request and claims no remote inventory.
            Input::Page {
                root,
                by,
                sort,
                recursive,
                entries,
                limit,
                cursor,
            } => json!({"status":"structured",
                "network_performed":false,
                "page":page(&root,&by,&sort,recursive,&entries,limit,cursor.as_deref())?}),
            Input::Integrity {
                action,
                mut manifest,
                docid,
                rev,
                length,
                raw_base64,
            } => {
                let bytes = Zeroizing::new(
                    STANDARD
                        .decode(raw_base64.0.as_bytes())
                        .map_err(|_| err("invalid_base64"))?,
                );
                match action {
                    IntegrityAction::Record => {
                        let sha256 = manifest.record(&docid, &rev, length, &bytes)?;
                        json!({"status":"structured","sha256":sha256,"manifest":manifest})
                    }
                    IntegrityAction::Verify => {
                        json!({"status":"structured","verified":manifest.verify(&docid,&rev,length,&bytes)})
                    }
                }
            }
            Input::Preview { intent } => {
                json!({"status":"structured","preview":Preview::new(intent)?.inspect()})
            }
        })
    };
    // Refusal reasons are fixed identifiers owned by this module, so they name
    // exactly which contract is missing. Parser diagnostics and supplied
    // material never reach the output.
    match execute() {
        Ok(value) => Ok(value),
        Err(error) => Ok(blocked(error.code)),
    }
}

pub fn schema() -> Value {
    let string = json!({"type":"string"});
    let optional_string = json!({"type":["string","null"]});
    let integer = json!({"type":"integer","minimum":0,"maximum":u64::MAX});
    let optional_integer = json!({"type":["integer","null"],"minimum":0,"maximum":u64::MAX});
    let entry = json!({"type":"object","additionalProperties":false,"required":["docid","name","rev","size"],
        "properties":{"docid":string,"name":string,"rev":string,"size":{"type":"integer","minimum":i64::MIN,"maximum":i64::MAX},"modified":{}}});
    let nonempty = json!({"type":"string","minLength":1});
    let sort_enum = json!({"enum":["asc","desc"]});
    let limited = json!({"type":"integer","minimum":1,"maximum":1000});
    // Every field is a caller-declared expectation; fields that cannot apply to
    // the chosen operation are refused rather than ignored.
    let intent = json!({"type":"object","additionalProperties":false,
        "required":["operation","target_path","parent_docid","expected_name"],
        "properties":{"operation":{"enum":["upload","move","copy","delete_file","delete_directory","rename","create_directory"]},
            "source_docid":optional_string,"source_rev":optional_string,"target_path":string,"parent_docid":string,
            "expected_name":string,"ondup":{"type":["integer","null"],"minimum":1,"maximum":3},
            "overwrites":{"type":["boolean","null"]},
            "byte_length":optional_integer,"local_sha256":optional_string},
        "allOf":[
            {"if":{"properties":{"operation":{"const":"upload"}}},"then":{
                "required":["byte_length","local_sha256","ondup","overwrites"],
                "properties":{"source_docid":{"type":"null"},"source_rev":{"type":"null"},
                    "ondup":{"type":"integer"},"overwrites":{"type":"boolean"}}}},
            {"if":{"properties":{"operation":{"const":"create_directory"}}},"then":{
                "required":["ondup","overwrites"],
                "properties":{"source_docid":{"type":"null"},"source_rev":{"type":"null"},
                    "byte_length":{"type":"null"},"local_sha256":{"type":"null"},
                    "ondup":{"type":"integer"},"overwrites":{"type":"boolean"}}}},
            {"if":{"properties":{"operation":{"enum":["move","copy"]}}},"then":{
                "required":["source_docid","source_rev","ondup","overwrites"],
                "properties":{"source_docid":string,"source_rev":string,"byte_length":{"type":"null"},
                    "local_sha256":{"type":"null"},"ondup":{"type":"integer"},"overwrites":{"type":"boolean"}}}},
            {"if":{"properties":{"operation":{"enum":["rename","delete_file","delete_directory"]}}},"then":{
                "required":["source_docid","source_rev"],
                "properties":{"source_docid":string,"source_rev":string,"byte_length":{"type":"null"},
                    "local_sha256":{"type":"null"},"ondup":{"type":"null"},"overwrites":{"type":"null"}}}}]});
    let mut branches = Vec::new();
    for (operation, required, mut properties) in [
        ("auth_url", vec!["host"], json!({"host":string})),
        (
            "login_challenge",
            vec!["raw_base64"],
            json!({"raw_base64":string,"content_type":optional_string}),
        ),
        (
            "token",
            vec![],
            json!({"code":optional_string,"public_key_pem":optional_string,"public_key_source":optional_string,"padding":optional_string}),
        ),
        (
            "list",
            vec!["host"],
            json!({"host":string,"access_token":optional_string,"remaining_seconds":optional_integer,
            "docid":optional_string,"by":optional_string,"sort":optional_string,"raw_base64":optional_string,"content_type":optional_string}),
        ),
        (
            "tree",
            vec![
                "host",
                "access_token",
                "remaining_seconds",
                "root",
                "by",
                "sort",
                "max_directories",
            ],
            json!({"host":string,"access_token":string,"remaining_seconds":integer,
            "root":nonempty,"by":nonempty,"sort":sort_enum,"max_directories":limited}),
        ),
        (
            "page",
            vec!["root", "by", "sort", "recursive", "entries", "limit"],
            json!({"root":nonempty,"by":nonempty,"sort":sort_enum,
            "recursive":{"type":"boolean"},"entries":{"type":"array","maxItems":MAX_SNAPSHOT_ENTRIES,"items":entry.clone()},
            "limit":limited,"cursor":optional_string}),
        ),
        (
            "integrity",
            vec!["action", "manifest", "docid", "rev", "length", "raw_base64"],
            json!({"action":{"enum":["record","verify"]},"manifest":{"type":"object","required":["records"],"properties":{"records":{"type":"object","additionalProperties":{"type":"string"}}}},"docid":string,"rev":string,"length":integer,"raw_base64":string}),
        ),
        ("preview", vec!["intent"], json!({"intent":intent})),
    ] {
        properties["operation"] = json!({"const":operation});
        let mut required = required;
        required.push("operation");
        branches.push(json!({"type":"object","additionalProperties":false,"required":required,"properties":properties}));
    }
    json!({"module":"drive","status":"pending","default_host":"bhpan.buaa.edu.cn",
        "input":{"oneOf":branches},
        "output":{"type":"object","required":["status"],"properties":{"status":{"enum":["structured","degraded","blocked"]}},
            "allOf":[{"if":{"required":["source"],"properties":{"source":{"const":"operator_supplied"}}},
                "then":{"required":["network_performed"],"properties":{"network_performed":{"const":false}}}}]},
        "offline_list_output":{"type":"object","required":["status","source","completeness","network_performed"],
            "properties":{"status":{"enum":["structured","degraded"]},"source":{"const":"operator_supplied"},
                "completeness":{"const":"single_response_body_pagination_unconfirmed"},
                "network_performed":{"const":false}}},
        "transport":"https_only","credential_authority_host":"bhpan.buaa.edu.cn",
        "blocked_capabilities":["oauth_authorization","token_exchange","directory_listing_request",
            "download_upload_transfer","mutation_commit","write_postconditions"],
        "oauth_authorization":{"status":"blocked","reason":"private_random_single_consumption_state_and_exchange_sink_unavailable"},
        "token_exchange":{"status":"blocked","network_performed":false,
            "paths":{"authorization_code":"requires_private_session_bound_state_and_a_non_receipt_sink",
                "password_encryption":"requires_admitted_platform_public_key_provenance_and_padding_contract"},
            "ambiguous_or_incomplete_request":"refused","padding_with_code":"refused",
            "secret_material_in_output":false},
        "directory_listing":{"status":"blocked","reason":"deployment_attr_contract_unconfirmed",
            "tree_is_partial_when_any_directory_read_fails":true,"tree_completion_reachable":false},
        "listing":{"status":"blocked","reason":"deployment_attr_contract_unconfirmed","retained_evidence_only":true,
            "completeness":"single_response_body_pagination_unconfirmed"},
        "authentication":{"status":"blocked",
            "reason":"platform_public_key_padding_and_key_provenance_not_supplied","credential_sources":["stdin","keyring"],
            "token_storage":"memory_only","automatic_refresh":false},
        "writes":{"status":"blocked","reason":"write_idempotency_and_postcondition_contract_not_admitted",
            "commit_supported":false,"preview_immutable":true,"confirmation_is_never_a_commit":true,
            "intent_required":["operation","target_path","parent_docid","expected_name"],
            "reference_operations_require":["source_docid","source_rev"],
            "upload_requires":["byte_length","local_sha256"],
            "destructive_operations":["move","copy","rename","delete_file","delete_directory"],
            "postconditions":[]},
        "pagination":{"origin":"client_snapshot","network_performed":false,
            "snapshot_max_entries":MAX_SNAPSHOT_ENTRIES,"limit":{"minimum":1,"maximum":1000},
            "cursor":{"encoding":"base64_standard","max_length":MAX_CURSOR_LEN,"version":CURSOR_VERSION,
                "binding_sha256_over":["root","by","sort","recursive","snapshot_entries","entries"]},
            "terminal":{"rule":"next_cursor_absent_if_and_only_if_complete","complete_field":"complete"},
            "refusals":["snapshot_duplicate_or_invalid_entry","snapshot_bound_exceeded",
                "cursor_snapshot_mismatch","zero_or_out_of_range_offset"]},
        "tree":{"completeness":["directories_read","pending_directories","complete","stop_reason"],
            "duplicate_or_cycle":"refused",
            "listing_pagination":"unconfirmed","inventory_completeness":"unproven",
            "bounds":{"max_directories":{"minimum":1,"maximum":1000},"max_entries":MAX_SNAPSHOT_ENTRIES}},
        "integrity":{"algorithm":"sha256","key":["docid","rev","length"],"rev_is_digest":false},
        "read_output":{"oneOf":[
            {"type":"object","required":["status","http_status","value"],"properties":{"status":{"const":"structured"},"http_status":{"type":"integer"},"value":{}}},
            {"type":"object","required":["status","http_status","evidence"],"properties":{"status":{"const":"degraded"},"http_status":{"type":"integer"},"evidence":{"type":"object","required":["raw_base64","content_type","byte_length","sha256","fallback_reason","raw_withheld"],"properties":{"raw_base64":{"type":"string"},"content_type":{"type":["string","null"]},"byte_length":{"type":"integer","minimum":0},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"fallback_reason":{"type":"string"},"raw_withheld":{"type":"boolean"},"raw_withheld_reason":{"type":"string"}}}}}
        ]},
        "page_output":{"type":"object","additionalProperties":false,"required":["status","network_performed","page"],
            "properties":{"status":{"const":"structured"},"network_performed":{"const":false},
                "page":{"type":"object","additionalProperties":false,
                    "required":["entries","offset","delivered","snapshot_entries","complete"],
                    "properties":{"entries":{"type":"array","items":entry},"offset":integer,
                        "delivered":integer,"snapshot_entries":integer,"complete":{"type":"boolean"},
                        "next_cursor":optional_string},
                    "allOf":[
                        {"if":{"properties":{"complete":{"const":true}}},"then":{"properties":{"next_cursor":{"type":"null"}}}},
                        {"if":{"properties":{"complete":{"const":false}}},"then":{"required":["next_cursor"],
                            "properties":{"next_cursor":{"type":"string"}}}}]}}},
        "tree_output":{"oneOf":[
            {"type":"object","required":["status","entries","directories_read","complete","listing_pagination"],
                "properties":{"status":{"const":"structured"},"entries":{"type":"array","items":entry},
                    "directories_read":integer,"complete":{"const":true},
                    "listing_pagination":{"const":"unconfirmed"}}},
            {"type":"object","required":["status","completed_entries","directories_read","pending_directories","complete","stop_reason","response"],
                "properties":{"status":{"const":"degraded"},"completed_entries":{"type":"array","items":entry},
                    "directories_read":integer,"pending_directories":integer,"complete":{"const":false},
                    "stop_reason":{"enum":["remote_read_degraded","unrecognized_dir_list"]},"response":{}}}]},
        "preview_output":{"type":"object","additionalProperties":false,"required":["status","preview"],
            "properties":{"status":{"const":"structured"},"preview":{"type":"object","additionalProperties":false,
                "required":["intent","confirmation","confirmation_binds","preview_immutable","commit_supported","postconditions","blocked_reason"],
                "properties":{"intent":intent,"confirmation":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                    "confirmation_binds":{"type":"array","items":{"type":"string"}},
                    "preview_immutable":{"const":true},"commit_supported":{"const":false},
                    "postconditions":{"type":"array","maxItems":0},
                    "blocked_reason":{"const":"write_idempotency_and_postcondition_contract_not_admitted"}}}}},
        "blocked_output":{"type":"object","additionalProperties":false,"required":["status","reason"],
            "properties":{"status":{"const":"blocked"},"reason":{"type":"string","minLength":1}}}})
}

// Fixed synthetic response scenarios exercise the same admission and projection
// used after a completed read, without constructing a client or a governor.
#[cfg(test)]
mod numeric_read_regression {
    use super::*;

    const BODY: &[u8] = br#"[{"docid":"d","n":1e3}]"#;
    const SAFE_BODY: &[u8] = br#"[{"docid":"d","n":42}]"#;
    const MIME: Option<&str> = Some("application/json");

    fn libraries_path() -> &'static str {
        let (path, request_body) = ReadEndpoint::Libraries.request().unwrap();
        assert!(request_body.is_none());
        path
    }

    #[test]
    pub(super) fn normalized_numeric_credential_is_withheld() {
        let error = admit_read_body(libraries_path(), 200, BODY, MIME, "1000.0", false)
            .err()
            .expect("numeric credential must not be projected");
        assert_eq!(error.code, "credential_echo_withheld");
        assert_eq!(error.message, "drive contract refused; no automatic retry");
    }

    #[test]
    pub(super) fn issued_session_cookie_is_refused_before_projection() {
        // This reader keeps no cookie jar, so a Set-Cookie response carries a
        // credential the caller never submitted and cannot revoke.
        let error = admit_read_body(
            libraries_path(),
            200,
            SAFE_BODY,
            MIME,
            "unrelated-secret",
            true,
        )
        .err()
        .expect("a response that issued a session cookie must not be projected");
        assert_eq!(error.code, "session_cookie_refused");
        // The same body without cookie issuance is admitted, so the refusal is
        // caused by issuance alone.
        assert!(
            admit_read_body(
                libraries_path(),
                200,
                SAFE_BODY,
                MIME,
                "unrelated-secret",
                false
            )
            .is_ok()
        );
    }

    fn assert_structured(body: &[u8], secret: &str, number: Value) {
        let result = admit_read_body(libraries_path(), 200, body, MIME, secret, false).unwrap();
        // read_output's network flag describes its production caller. This is
        // a synthetic direct call and does not claim an actual request.
        assert_eq!(
            result,
            json!({
                "status":"structured", "http_status":200, "network_performed":true,
                "value":[{"docid":"d","n":number}],
                "source":{
                    "raw_base64":STANDARD.encode(body), "content_type":"application/json",
                    "byte_length":body.len(), "sha256":digest(body),
                    "fallback_reason":"retained_original", "raw_withheld":false
                }
            })
        );
    }

    #[test]
    pub(super) fn numeric_credential_controls() {
        assert_structured(BODY, "unrelated-secret", json!(1000.0));
        assert_structured(SAFE_BODY, "1000.0", json!(42));
    }

    #[test]
    pub(super) fn independent_denials_remain_recognized() {
        // Client::read classifies this response before admission and retains
        // the classification for lease settlement; no lease is opened here.
        assert_eq!(rejection_code(BODY), None);
        assert_eq!(
            rejection_code(br#"{"code":401001003,"n":1e3}"#),
            Some(401001003)
        );
        let error = admit_read_body(libraries_path(), 200, BODY, MIME, "unrelated-secret", true)
            .unwrap_err();
        assert_eq!(error.code, "session_cookie_refused");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_source_never_claims_network() {
        for online in [false, true] {
            let output=run(&json!({"operation":"list","host":"bhpan.buaa.edu.cn", "raw_base64":STANDARD.encode(br#"{"dirs":[],"files":[]}"#),"content_type":"application/json"}).to_string(),online).unwrap();
            assert_eq!(output["status"], "structured");
            assert_eq!(output["source"], "operator_supplied");
            // One supplied body is never claimed as a complete inventory.
            assert_eq!(
                output["completeness"],
                "single_response_body_pagination_unconfirmed"
            );
            assert_eq!(output["network_performed"], false);
        }
    }
    #[test]
    fn error_json_is_not_success() {
        for status in [200, 400, 404] {
            let bytes = br#"{"code":404006,"message":"synthetic missing"}"#;
            let output = read_output("/dir/list", status, bytes, Some("application/json"));
            assert_eq!(output["status"], "degraded");
            assert_eq!(output["evidence"]["raw_base64"], STANDARD.encode(bytes));
        }
        assert_eq!(
            read_output(
                "/dir/list",
                200,
                br#"{"dirs":[],"files":[]}"#,
                Some("application/json")
            )["status"],
            "structured"
        );
        assert_eq!(
            read_output("/dir/list", 404, br#"{"dirs":[],"files":[]}"#, None)["status"],
            "degraded"
        );
    }
    #[test]
    fn credential_rejection_keeps_cooldown() {
        use std::os::unix::fs::DirBuilderExt;
        for body_failed in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "drive-settlement-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                body_failed
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            let governor = Governor::isolated_for_test(&path).unwrap();
            let lease = governor
                .try_acquire(crate::governor::RequestKind::Interactive)
                .unwrap();
            settle_response(
                lease,
                429,
                Some("1800"),
                false,
                body_failed,
                Some(401001003),
            )
            .unwrap();
            let state = governor.status().unwrap();
            assert!(!state.safety_latched);
            assert!(state.cooldown_wait > std::time::Duration::from_secs(1700));
            assert!(
                governor
                    .try_acquire(crate::governor::RequestKind::Interactive)
                    .is_err()
            );
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn unified_offline_dispatch() {
        let unsafe_url = run(
            r#"{"operation":"auth_url","host":"bhpan.buaa.edu.cn"}"#,
            false,
        )
        .unwrap();
        assert_eq!(unsafe_url["status"], "blocked");
        assert_eq!(unsafe_url["reason"], "oauth_authorization_state_unsafe");
        assert_eq!(unsafe_url["network_performed"], Value::Null);
        let challenge =
            STANDARD.encode(br#"{"challenge":"secret_fixture","csrftoken":"csrf_fixture"}"#);
        let output = run(
            &json!({"operation":"login_challenge","raw_base64":challenge}).to_string(),
            false,
        )
        .unwrap();
        assert_eq!(output["challenge_present"], true);
        assert!(!output.to_string().contains("secret_fixture"));
        assert_eq!(
            run(r#"{"operation":"list","host":"bhpan.buaa.edu.cn"}"#, false).unwrap()["status"],
            "blocked"
        );
        assert_eq!(
            run(r#"{"operation":"token","code":"secret_fixture"}"#, true).unwrap()["status"],
            "blocked"
        );
        assert_eq!(
            run(
                r#"{"operation":"auth_url","host":"bhpan.buaa.edu.cn","unexpected":true}"#,
                false
            )
            .unwrap()["status"],
            "blocked"
        );
        let record=run(&json!({"operation":"integrity","action":"record","manifest":{"records":{}},"docid":"id","rev":"r","length":3,"raw_base64":STANDARD.encode(b"abc")}).to_string(),false).unwrap();
        let verify=run(&json!({"operation":"integrity","action":"verify","manifest":record["manifest"],"docid":"id","rev":"r","length":3,"raw_base64":STANDARD.encode(b"abc")}).to_string(),false).unwrap();
        assert_eq!(verify["verified"], true);
        // Every accepted operation appears in the published input union.
        let branches = schema()["input"]["oneOf"].as_array().unwrap().clone();
        assert_eq!(branches.len(), 8);
        for operation in [
            "auth_url",
            "login_challenge",
            "token",
            "list",
            "tree",
            "page",
            "integrity",
            "preview",
        ] {
            assert!(
                branches
                    .iter()
                    .any(|branch| branch["properties"]["operation"]["const"] == json!(operation)),
                "{operation}"
            );
        }
        assert_eq!(
            run(
                r#"["list",{"host":"bhpan.buaa.edu.cn","access_token":"opaque123"}]"#,
                false
            )
            .unwrap()["reason"],
            "invalid_input_or_unknown_field"
        );
        assert_eq!(
            run(
                r#"[{"host":"bhpan.buaa.edu.cn","access_token":"opaque123"}]"#,
                false
            )
            .unwrap()["reason"],
            "invalid_input_or_unknown_field"
        );
        assert!(
            !run(
                r#"["list",{"host":"bhpan.buaa.edu.cn","access_token":"opaque123"}]"#,
                false
            )
            .unwrap()
            .to_string()
            .contains("opaque123")
        );
    }
    fn entry(id: &str) -> Entry {
        Entry {
            docid: id.into(),
            name: id.into(),
            rev: "v1".into(),
            size: 1,
            modified: Value::Null,
        }
    }
    #[test]
    fn login_contract() {
        assert!(auth_url(AUTHORITY_HOST).is_err());
        assert!(auth_url("evil.example").is_err());
        assert!(
            LoginChallenge::parse(
                br#"<script>{"challenge":"synthetic","csrftoken":"synthetic"}</script>"#
            )
            .unwrap()
            .ready()
        );
        assert!(
            LoginChallenge::parse(br#"{"challenge":"a","challenge":"b","csrftoken":"c"}"#).is_err()
        );
        assert!(
            authorization_code("anyshare://oauth2/login/callback?code=fixture&state=any").is_err()
        );
        assert!(authorization_code("https://evil.invalid/?code=fixture&state=bad").is_err());
        assert_eq!(schema()["authentication"]["status"], "blocked");
        assert_eq!(
            run(
                r#"{"operation":"auth_url","host":"bhpan.buaa.edu.cn"}"#,
                false
            )
            .unwrap()["reason"],
            "oauth_authorization_state_unsafe"
        );
    }
    #[test]
    fn listing_and_fallback() {
        let bytes =
            br#"{"dirs":[],"files":[{"docid":"a","name":"a","rev":"v","size":1,"creator":"x"}]}"#;
        assert!(matches!(
            parse_listing(bytes, Some("application/json")),
            Listing::Structured { .. }
        ));
        let Listing::Degraded { evidence } = parse_listing(b"opaque", Some("text/plain")) else {
            panic!()
        };
        assert_eq!(STANDARD.decode(evidence.raw_base64).unwrap(), b"opaque");
        assert_eq!(evidence.content_type.as_deref(), Some("text/plain"));
        assert_eq!(evidence.sha256, digest(b"opaque"));
    }
    #[test]
    fn unsafe_fallback_withholds_raw_but_keeps_provenance() {
        for (bytes, ct, reason) in [
            (
                b"<input name=captcha value=unsafe>".as_slice(),
                Some("text/html"),
                "challenge_detected",
            ),
            (b"opaque".as_slice(), None, "response_safety_unreviewed"),
        ] {
            let evidence = Evidence::new(bytes, ct, "unrecognized_dir_list");
            assert!(evidence.raw_withheld);
            assert!(evidence.raw_base64.is_empty());
            assert_eq!(evidence.raw_withheld_reason.as_deref(), Some(reason));
            assert_eq!(evidence.sha256, digest(bytes));
            assert_eq!(evidence.byte_length, bytes.len());
        }
        assert!(response_contains_secret(
            br#"{"message":"echo private\"token"}"#,
            None,
            "private\"token"
        ));
        assert!(response_contains_secret(
            b"safe",
            Some("text/plain; private-token"),
            "private-token"
        ));
        let evidence = Evidence::new(
            b"new access_token=private-material",
            Some("text/plain"),
            "unrecognized",
        );
        assert!(evidence.raw_withheld);
        assert!(evidence.raw_base64.is_empty());
    }
    #[test]
    fn partial_challenge_and_header_facts_settle_on_original_lease() {
        use std::os::unix::fs::DirBuilderExt;
        for (index, (bytes, header, expected_latch)) in [
            (b"<input name=captcha>".as_slice(), false, true),
            (b"ordinary prefix".as_slice(), true, true),
            (b"ordinary prefix".as_slice(), false, false),
        ]
        .into_iter()
        .enumerate()
        {
            let path = std::env::temp_dir().join(format!(
                "drive-tristate-{}-{}-{index}",
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
            let governor = Governor::isolated_for_test(&path).unwrap();
            let lease = governor
                .try_acquire(crate::governor::RequestKind::Interactive)
                .unwrap();
            let assessment = crate::html::assess_challenge_body(bytes, Some("text/html"), false);
            settle_response(
                lease,
                200,
                Some("1800"),
                header || assessment == crate::html::ChallengeAssessment::Detected,
                true,
                None,
            )
            .unwrap();
            let state = governor.status().unwrap();
            assert_eq!(state.safety_latched, false);
            assert!(state.cooldown_wait > std::time::Duration::from_secs(1700));
            if !header && !expected_latch {
                assert_eq!(assessment, crate::html::ChallengeAssessment::Unreviewed);
            }
            std::fs::remove_dir_all(path).unwrap();
        }
    }
    #[test]
    fn decoded_credentials_and_offline_mime_are_gated() {
        assert!(response_contains_secret(
            br#"{"echo":"\u006fpaque123"}"#,
            Some("application/json"),
            "opaque123"
        ));
        assert!(response_contains_secret(
            br#"{"\u006fpaque123":0}"#,
            Some("application/json"),
            "opaque123"
        ));
        let body=br#"{"quota_used":0,"quota_allocated":1,"space_rate":0,"\u0061ccess_token":"fresh-material"}"#;
        let out = read_output("/quota/user", 200, body, Some("application/json"));
        assert_eq!(out["status"], "degraded");
        assert!(!out.to_string().contains("fresh-material"));
        assert_eq!(out["evidence"]["raw_withheld"], true);
        for mime in [None, Some("application/xhtml+xml")] {
            assert!(matches!(
                parse_listing(br#"{"dirs":[],"files":[]}"#, mime),
                Listing::Degraded { .. }
            ));
        }
        let out=run(&json!({"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"opaque123","raw_base64":STANDARD.encode(br#"{"dirs":[],"files":[]}"#),"content_type":"application/xhtml+xml"}).to_string(),true).unwrap();
        assert_eq!(out["status"], "degraded");
        assert_eq!(out["source"], "operator_supplied");
        assert_eq!(out["network_performed"], false);
        let output=run(&json!({"operation":"list","host":"evil.example","raw_base64":STANDARD.encode(br#"{"dirs":[],"files":[]}"#),"content_type":"application/json"}).to_string(),false).unwrap();
        assert_eq!(output["status"], "structured");
        assert_eq!(output["source"], "operator_supplied");
        assert_eq!(output["network_performed"], false);
        let offline = run(
            &json!({"operation":"list","host":"evil.example"}).to_string(),
            false,
        )
        .unwrap();
        assert_eq!(offline["status"], "blocked");
        assert_eq!(offline["network_performed"], Value::Null);
        for online in [false, true] {
            assert_eq!(run(&json!({"operation":"list","host":"evil.example","access_token":"opaque123","remaining_seconds":60}).to_string(),online).unwrap()["status"],"blocked");
        }
        let out=run(&json!({"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"opaque123","raw_base64":STANDARD.encode(br#"{"echo":"\u006fpaque123"}"#),"content_type":"application/json"}).to_string(),false).unwrap();
        assert_eq!(out["evidence"]["raw_withheld"], true);
        assert_eq!(out["network_performed"], false);
        assert!(!out.to_string().contains("opaque123"));
        let input = Input::parse(
            r#"{"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"opaque123"}"#,
        )
        .unwrap();
        if let Input::List {
            access_token: Some(token),
            ..
        } = input
        {
            let _: &Zeroizing<String> = &token.0;
        } else {
            panic!("typed token absent");
        }
        assert!(
            serde_json::from_slice::<PrivateValue>(br#"{"first":"private","first":"duplicate"}"#)
                .is_err()
        );
    }
    #[test]
    fn metadata_echoes_are_sanitized() {
        let bytes = br#"{"access_token":"freshopaque123"}"#;
        let ct = "application/json; proof=freshopaque123";
        let evidence = Evidence::new(bytes, Some(ct), "sensitive");
        assert_eq!(
            evidence.raw_withheld_reason.as_deref(),
            Some("sensitive_response_material")
        );
        assert_eq!(evidence.content_type.as_deref(), Some("application/json"));
        assert!(
            !serde_json::to_string(&evidence)
                .unwrap()
                .contains("freshopaque123")
        );
        let out=run(&json!({"operation":"login_challenge","raw_base64":"eA==","content_type":"text/html; access_token=fresh-material"}).to_string(),false).unwrap();
        assert_eq!(out["status"], "blocked");
        assert_eq!(out["content_type"], "text/html");
        assert!(!out.to_string().contains("fresh-material"));
        for online in [false, true] {
            assert_eq!(run(&json!({"operation":"list","host":"collector.example","access_token":"opaque123","remaining_seconds":60}).to_string(),online).unwrap()["status"],"blocked");
        }
    }
    #[test]
    fn nested_shape_and_encoded_echo_contracts() {
        assert!(response_contains_secret(
            b"echo=abc%2B123",
            Some("text/plain"),
            "abc+123"
        ));
        for input in [
            r#"{"operation":"preview","intent":["rename",null,null,"private","parent","name",1,false,0,null]}"#,
            r#"{"operation":"page","root":"root","by":"name","sort":"asc","recursive":false,"entries":[["d","private","r",1,null]],"limit":10}"#,
            r#"{"operation":"integrity","action":"record","manifest":[{}],"docid":"d","rev":"r","length":0,"raw_base64":""}"#,
        ] {
            assert_eq!(
                run(input, false).unwrap()["reason"],
                "invalid_input_or_unknown_field"
            );
        }
        assert_eq!(
            run(
                " \n {\"operation\":\"auth_url\",\"host\":\"bhpan.buaa.edu.cn\"} \t",
                false
            )
            .unwrap()["reason"],
            "oauth_authorization_state_unsafe"
        );
        assert!(
            ReadEndpoint::List {
                docid: "d".into(),
                by: "name".into(),
                sort: "asc".into()
            }
            .request()
            .is_err()
        );
        assert!(ReadEndpoint::Quota.request().is_ok());
    }
    #[test]
    fn composed_encoding_and_duplicate_facts() {
        let evidence = Evidence::new(
            b"%61%63%63%65%73%73%5F%74%6F%6B%65%6E=opaqueABC123",
            Some("application/x-www-form-urlencoded"),
            "shape",
        );
        assert!(evidence.raw_withheld);
        assert!(evidence.raw_base64.is_empty());
        assert!(response_contains_secret(
            br#"{"echo":"abc%2B\u0031\u0032\u0033"}"#,
            Some("application/json"),
            "abc+123"
        ));
        assert_eq!(
            rejection_code(br#"{"code":401001001,"note":0,"note":1}"#),
            Some(401001001)
        );
        assert_eq!(
            rejection_code(br#"{"note":0,"note":1,"code":"401001003"}"#),
            Some(401001003)
        );
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
    #[test]
    fn repeated_retry_after_survives_body_failure() {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "drive-many-retry-{}-{}",
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
        let governor = Governor::isolated_for_test(&path).unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            "retry-after",
            reqwest::header::HeaderValue::from_static("0"),
        );
        headers.append(
            "retry-after",
            reqwest::header::HeaderValue::from_static("1800"),
        );
        headers.append(
            "retry-after",
            reqwest::header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        let mut lease = governor
            .try_acquire(crate::governor::RequestKind::Interactive)
            .unwrap();
        lease
            .observe_http_many(
                429,
                headers
                    .get_all("retry-after")
                    .iter()
                    .map(|value| value.to_str().ok()),
                false,
            )
            .unwrap();
        settle_response(lease, 429, Some("0"), false, true, None).unwrap();
        assert!(governor.status().unwrap().cooldown_wait > std::time::Duration::from_secs(1700));
        drop(governor);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn cursor_binds_snapshot() {
        let entries = vec![entry("a"), entry("b")];
        let first = page("root", "name", "asc", false, &entries, 1, None).unwrap();
        let c = first.next_cursor.as_deref();
        assert_eq!(
            page("root", "name", "asc", false, &entries, 1, c)
                .unwrap()
                .entries[0]
                .docid,
            "b"
        );
        assert!(page("other", "name", "asc", false, &entries, 1, c).is_err());
        assert!(page("root", "name", "asc", true, &entries, 1, c).is_err());
        assert!(page("root", "name", "desc", false, &entries, 1, c).is_err());
        assert!(
            page(
                "root",
                "name",
                "asc",
                false,
                &[entry("a"), entry("c")],
                1,
                c
            )
            .is_err()
        );
    }
    #[test]
    fn pagination_is_bounded_terminal_and_duplicate_free() {
        let entries = vec![entry("a"), entry("b"), entry("c")];
        let first = page("root", "name", "asc", false, &entries, 2, None).unwrap();
        assert_eq!(
            (first.offset, first.delivered, first.snapshot_entries),
            (0usize, 2, 3)
        );
        assert!(!first.complete);
        assert!(first.next_cursor.is_some());
        let cursor = first.next_cursor.as_deref().unwrap().to_owned();
        let last = page(
            "root",
            "name",
            "asc",
            false,
            &entries,
            2,
            Some(cursor.as_str()),
        )
        .unwrap();
        assert_eq!((last.offset, last.delivered), (2usize, 1));
        // The explicit terminal fact and the absent cursor always agree, so a
        // page chain cannot loop or silently stop early.
        assert!(last.complete);
        assert_eq!(last.next_cursor, None);
        // A duplicate docid cannot be paginated as a complete listing.
        assert_eq!(
            page(
                "root",
                "name",
                "asc",
                false,
                &[entry("a"), entry("a")],
                1,
                None
            )
            .err()
            .unwrap()
            .code,
            "snapshot_duplicate_or_invalid_entry"
        );
        // An empty snapshot is explicitly complete, not an absent page.
        let empty = page("root", "name", "asc", false, &[], 10, None).unwrap();
        assert!(empty.complete && empty.next_cursor.is_none() && empty.delivered == 0);
        // The binding covers the snapshot length as well as its content.
        assert_eq!(
            page(
                "root",
                "name",
                "asc",
                false,
                &[entry("a"), entry("b")],
                2,
                Some(cursor.as_str())
            )
            .err()
            .unwrap()
            .code,
            "cursor_snapshot_mismatch"
        );
        assert_eq!(
            page("", "name", "asc", false, &entries, 1, None)
                .err()
                .unwrap()
                .code,
            "invalid_page"
        );
        assert_eq!(
            page("root", "name", "sideways", false, &entries, 1, None)
                .err()
                .unwrap()
                .code,
            "invalid_page"
        );
        assert_eq!(
            page("root", "", "asc", false, &entries, 1, None)
                .err()
                .unwrap()
                .code,
            "invalid_page"
        );
    }
    fn token_reason(input: &str) -> String {
        let output = run(input, false).unwrap();
        assert_eq!(output["status"], "blocked");
        // A refused exchange never claims a request, and never echoes material.
        assert_eq!(output["network_performed"], Value::Null);
        output["reason"].as_str().unwrap().to_owned()
    }
    const PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----";
    #[test]
    fn token_exchange_is_strict_and_never_attempted() {
        assert_eq!(
            token_reason(r#"{"operation":"token"}"#),
            "token_exchange_credential_path_missing"
        );
        // A padding choice beside an authorization code is ambiguous.
        assert_eq!(
            token_reason(r#"{"operation":"token","code":"private-code","padding":"pkcs1"}"#),
            "token_exchange_path_ambiguous"
        );
        // Both credential paths in one request is ambiguous as well.
        assert_eq!(
            token_reason(
                &json!({"operation":"token","code":"private-code",
            "public_key_source":"operator_file","padding":"pkcs1"})
                .to_string()
            ),
            "token_exchange_path_ambiguous"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_source":"operator_file",
            "padding":"pkcs1"})
                .to_string()
            ),
            "public_key_material_incomplete"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":PEM,
            "padding":"pkcs1"})
                .to_string()
            ),
            "public_key_provenance_missing"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":{"not":"a pem"},
            "public_key_source":"operator_file","padding":"pkcs1"})
                .to_string()
            ),
            "invalid_input_or_unknown_field"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":"not-a-pem",
            "public_key_source":"operator_file","padding":"pkcs1"})
                .to_string()
            ),
            "public_key_pem_invalid"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":PEM,
            "public_key_source":"","padding":"pkcs1"})
                .to_string()
            ),
            "public_key_provenance_invalid"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":PEM,
            "public_key_source":"operator_file"})
                .to_string()
            ),
            "padding_contract_missing"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":PEM,
            "public_key_source":"operator_file","padding":"pkcs1 v1.5"})
                .to_string()
            ),
            "padding_contract_invalid"
        );
        // Well-formed declarations of either path are still refused outright.
        assert_eq!(
            token_reason(r#"{"operation":"token","code":"private-code"}"#),
            "authorization_code_exchange_requires_private_session_bound_state_and_a_non_receipt_sink"
        );
        assert_eq!(
            token_reason(
                &json!({"operation":"token","public_key_pem":PEM,
            "public_key_source":"operator_file","padding":"pkcs1_v1_5"})
                .to_string()
            ),
            "password_encryption_requires_admitted_platform_public_key_provenance_and_padding_contract"
        );
        // No supplied credential material appears in any refusal.
        let output = run(
            &json!({"operation":"token","code":"private-code-fixture",
            "public_key_pem":PEM})
            .to_string(),
            true,
        )
        .unwrap();
        let text = output.to_string();
        assert!(!text.contains("private-code-fixture"));
        assert!(!text.contains("MIIB"));
        for online in [false, true] {
            assert_eq!(
                run(
                    r#"{"operation":"token","code":"private-code-fixture"}"#,
                    online
                )
                .unwrap()["status"],
                "blocked"
            );
        }
        assert_eq!(schema()["token_exchange"]["status"], "blocked");
        assert_eq!(schema()["token_exchange"]["network_performed"], false);
        assert_eq!(
            schema()["token_exchange"]["secret_material_in_output"],
            false
        );
    }
    #[test]
    fn local_integrity() {
        let mut manifest = IntegrityManifest::default();
        manifest.record("id", "revision", 3, b"abc").unwrap();
        assert!(manifest.verify("id", "revision", 3, b"abc"));
        assert!(!manifest.verify("id", "revision", 3, b"abd"));
        assert!(!manifest.verify("id", "revision", 2, b"ab"));
        assert!(manifest.record("id", "revision", 3, b"abd").is_err());
    }
    #[test]
    fn write_confirmation_is_not_commit() {
        let preview = Preview::new(reference_intent(Mutation::Rename)).unwrap();
        assert!(preview.confirm("wrong", true).is_err());
        assert!(preview.confirm(&preview.confirmation, false).is_err());
        // A matching, explicitly confirmed preview is still not a remote write.
        let error = preview.confirm(&preview.confirmation, true).unwrap_err();
        assert_eq!(
            error.code,
            "mutation_blocked_missing_idempotency_and_postcondition_contract"
        );
        let inspected = preview.inspect();
        assert_eq!(inspected["commit_supported"], false);
        assert_eq!(inspected["preview_immutable"], true);
        assert_eq!(inspected["postconditions"], json!([]));
        // The confirmation binds the whole intent, so any change is a new preview.
        let mut changed = reference_intent(Mutation::Rename);
        changed.expected_name = "other".into();
        assert_ne!(
            Preview::new(changed).unwrap().confirmation,
            preview.confirmation
        );
        // Destructive operations are refused exactly like the rest.
        for operation in [Mutation::Move, Mutation::Copy] {
            let preview = Preview::new(colliding_intent(operation)).unwrap();
            assert!(preview.confirm(&preview.confirmation, true).is_err());
        }
        for operation in [Mutation::DeleteFile, Mutation::DeleteDirectory] {
            let preview = Preview::new(reference_intent(operation)).unwrap();
            assert!(preview.confirm(&preview.confirmation, true).is_err());
        }
        // The published schema must not claim any enabled write path.
        let writes = &schema()["writes"];
        assert_eq!(writes["status"], "blocked");
        assert_eq!(writes["commit_supported"], false);
        assert_eq!(writes["preview_immutable"], true);
        assert_eq!(writes["postconditions"], json!([]));
        assert!(
            schema()["blocked_capabilities"]
                .as_array()
                .unwrap()
                .contains(&json!("mutation_commit"))
        );
    }
    fn reference_intent(operation: Mutation) -> Intent {
        Intent {
            operation,
            source_docid: Some("id".into()),
            source_rev: Some("r".into()),
            target_path: "/target".into(),
            parent_docid: "parent".into(),
            expected_name: "name".into(),
            ondup: None,
            overwrites: None,
            byte_length: None,
            local_sha256: None,
        }
    }
    fn colliding_intent(operation: Mutation) -> Intent {
        Intent {
            ondup: Some(1),
            overwrites: Some(false),
            ..reference_intent(operation)
        }
    }
    fn create_intent(operation: Mutation) -> Intent {
        Intent {
            operation,
            source_docid: None,
            source_rev: None,
            target_path: "/target".into(),
            parent_docid: "parent".into(),
            expected_name: "name".into(),
            ondup: Some(1),
            overwrites: Some(false),
            byte_length: None,
            local_sha256: None,
        }
    }
    #[test]
    fn intent_must_be_exact_for_its_operation() {
        // Reference operations bind the exact object they observed.
        assert!(Preview::new(reference_intent(Mutation::DeleteFile)).is_ok());
        assert!(Preview::new(colliding_intent(Mutation::Move)).is_ok());
        assert!(Preview::new(colliding_intent(Mutation::Copy)).is_ok());
        let mut unbound = reference_intent(Mutation::DeleteFile);
        unbound.source_rev = None;
        assert_eq!(
            Preview::new(unbound).unwrap_err().code,
            "intent_source_partial"
        );
        let mut sourced = reference_intent(Mutation::Rename);
        sourced.source_docid = None;
        sourced.source_rev = None;
        assert_eq!(
            Preview::new(sourced).unwrap_err().code,
            "intent_source_required"
        );
        let mut transfer = reference_intent(Mutation::Rename);
        transfer.byte_length = Some(3);
        assert_eq!(
            Preview::new(transfer).unwrap_err().code,
            "transfer_facts_not_applicable"
        );
        let mut collision = reference_intent(Mutation::Rename);
        collision.ondup = Some(1);
        collision.overwrites = Some(false);
        assert_eq!(
            Preview::new(collision).unwrap_err().code,
            "collision_policy_not_applicable"
        );
        // Create-like operations never claim a source object.
        assert!(Preview::new(create_intent(Mutation::CreateDirectory)).is_ok());
        let mut create = create_intent(Mutation::CreateDirectory);
        create.byte_length = Some(3);
        assert_eq!(
            Preview::new(create).unwrap_err().code,
            "transfer_facts_not_applicable"
        );
        let mut ambiguous = create_intent(Mutation::CreateDirectory);
        ambiguous.ondup = Some(2);
        ambiguous.overwrites = Some(false);
        assert_eq!(
            Preview::new(ambiguous).unwrap_err().code,
            "ambiguous_or_silent_ondup"
        );
        let mut missing = create_intent(Mutation::Upload);
        missing.ondup = None;
        missing.overwrites = None;
        assert_eq!(
            Preview::new(missing).unwrap_err().code,
            "ondup_semantics_unconfirmed"
        );
        // An upload is exactly length plus digest under a declared collision policy.
        let upload = Intent {
            byte_length: Some(3),
            local_sha256: Some("a".repeat(64)),
            ..create_intent(Mutation::Upload)
        };
        assert!(Preview::new(upload.clone()).is_ok());
        let mut no_length = upload.clone();
        no_length.byte_length = None;
        assert_eq!(
            Preview::new(no_length).unwrap_err().code,
            "upload_length_required"
        );
        let mut bad_digest = upload;
        bad_digest.local_sha256 = Some("A".repeat(64));
        assert_eq!(
            Preview::new(bad_digest).unwrap_err().code,
            "upload_digest_required"
        );
        let mut sourced_upload = create_intent(Mutation::Upload);
        sourced_upload.byte_length = Some(0);
        sourced_upload.local_sha256 = Some("a".repeat(64));
        sourced_upload.source_docid = Some("id".into());
        sourced_upload.source_rev = Some("r".into());
        assert_eq!(
            Preview::new(sourced_upload).unwrap_err().code,
            "intent_source_not_applicable"
        );
    }
    #[test]
    fn reversible_credential_encodings_and_issued_cookie_are_detected() {
        for body in [
            br#"{"docid":"YWJjXzEyMw==","name":"safe"}"#.as_slice(),
            br#"{"docid":"\u0059WJjXzEyMw==","name":"safe"}"#.as_slice(),
            br#"{"docid":"%61%62%63%5F%31%32%33","name":"safe"}"#.as_slice(),
        ] {
            let error = admit_read_body(
                "/file/metadata",
                200,
                body,
                Some("application/json"),
                "abc_123",
                false,
            )
            .unwrap_err();
            assert_eq!(error.code, "credential_echo_withheld");
            assert_eq!(error.message, "drive contract refused; no automatic retry");
        }
        let body = br#"{"docid":"freshopaque123","name":"safe"}"#;
        let error = admit_read_body(
            "/file/metadata",
            200,
            body,
            Some("application/json"),
            "abc_123",
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, "session_cookie_refused");
        assert_eq!(error.message, "drive contract refused; no automatic retry");
        let safe = admit_read_body(
            "/file/metadata",
            200,
            body,
            Some("application/json"),
            "abc_123",
            false,
        )
        .unwrap();
        assert_eq!(safe["status"], "structured");
        assert_eq!(safe["value"]["docid"], "freshopaque123");
    }
    #[test]
    fn escaped_credential_echo_in_duplicate_member_body_is_withheld() {
        // The JSON string literal `path\/value` decodes to the credential
        // `path/value`; duplicate `x` members must not let the escaped echo
        // reach raw evidence.
        let echo = run(
            &json!({"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"path/value",
                "raw_base64":STANDARD.encode(br#"{"x":1,"x":2,"y":"path\/value"}"#),
                "content_type":"application/json"})
            .to_string(),
            false,
        )
        .unwrap();
        assert_eq!(echo["status"], "degraded");
        assert_eq!(echo["evidence"]["raw_withheld"], true);
        assert_eq!(echo["evidence"]["raw_base64"], "");
        assert!(!echo.to_string().contains("path/value"));
        assert_eq!(echo["network_performed"], false);
        // A harmless duplicate member without credential material still
        // preserves the exact supplied bytes.
        let safe = br#"{"x":1,"x":2,"y":"path/other"}"#;
        let control = run(
            &json!({"operation":"list","host":"bhpan.buaa.edu.cn","access_token":"path/value",
                "raw_base64":STANDARD.encode(safe),"content_type":"application/json"})
            .to_string(),
            false,
        )
        .unwrap();
        assert_eq!(control["status"], "degraded");
        assert_eq!(control["evidence"]["raw_withheld"], false);
        assert_eq!(control["evidence"]["raw_base64"], STANDARD.encode(safe));
    }
}

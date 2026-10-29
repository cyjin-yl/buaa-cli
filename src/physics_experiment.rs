//! Offline physics-selection previews and operator-fixture replay.
//!
//! No authenticated physics service is bound to this adapter, so this module
//! performs no network access and creates no private state. It offers a
//! deterministic selection preview and a replay of operator-supplied fixture
//! bytes through the shared non-executing HTML admission helpers.
//!
//! Authentication, captcha, session, selection submission and withdrawal stay
//! unsupported: no service contract is admitted for them, so no credential
//! field is accepted, copied or retained. A fixture that carries credential,
//! session or challenge material, or one whose safety cannot be reviewed,
//! keeps only its length and digest. Neither raw bytes nor parsed fields are
//! echoed back, because an encoding is not a redaction. A control's inactive
//! state is not evidence that its contents are safe to disclose. Privacy
//! scans include inactive text; business parsing still uses active text only.
//! A consumed character reference's own output cannot split a private marker:
//! a bounded second native parse records which references html5ever actually
//! consumed, and any provenance ambiguity or bound overflow stays unreviewed
//! instead of authorizing disclosure. Fallback markup that is never parsed as
//! controls stays unreviewed.
//! A supplied MIME must admit HTML semantics with valid, quote-aware charset
//! parameters. XHTML and unknown media types remain unreviewed. No supplied
//! Content-Type retains the explicit legacy GBK HTML-fixture convention.

use crate::html::{ChallengeAssessment, assess_challenge_body};
use crate::net::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ego_tree::NodeRef;
use html5ever::tokenizer::{TagKind, Token};
use html5ever::QualName;
use scraper::{ElementRef, Html, Node};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use zeroize::Zeroizing;

const MAX_INPUT: usize = 4 * 1024 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;
const CODE_LABEL: &str = "分组代号：";
const SEATS_LABEL: &str = "剩余空位：";
/// Elements laid out inline. Their text keeps its adjacency, so a number split
/// across inline markup stays one number. Every other element, including an
/// unknown one, ends the run. Replaced content such as an image, a progress
/// widget or a meter widget is not transparent text and ends the run too.
const INLINE_ELEMENTS: &[&str] = &[
    "a", "abbr", "acronym", "b", "bdi", "bdo", "big", "cite", "code", "data", "del", "dfn", "em",
    "font", "i", "ins", "kbd", "label", "mark", "nobr", "output", "q", "rp", "rt", "ruby", "s",
    "samp", "small", "span", "strike", "strong", "sub", "sup", "time", "tt", "u", "var", "wbr",
];
/// Credential, session and one-time-code vocabulary that must never leave
/// this adapter through an output envelope.
const SENSITIVE_MARKERS: &[&[u8]] = &[
    b"password",
    b"passwd",
    b"passphrase",
    b"pwd",
    b"txtpwd",
    b"txtuid",
    b"txtchk",
    b"credential",
    b"cookie",
    b"authorization",
    b"bearer",
    b"ticket",
    b"nonce",
    b"jwt",
    b"secret",
    b"session",
    b"token",
    b"csrf",
    b"xsrf",
    b"execution",
    b"loginname",
    b"login_name",
    b"username",
    b"user_name",
    b"one-time-code",
    b"verificationtoken",
    b"antiforgerytoken",
    b"requestverificationtoken",
];
/// Challenge and verification vocabulary. A control may carry it without
/// being interactive, so it is private either way.
const CHALLENGE_PRIVACY_MARKERS: &[&[u8]] = &[
    b"captcha",
    b"challenge",
    b"turnstile",
    b"verificationcode",
    b"verification-code",
    b"verification_code",
    b"verification code",
    b"onetimecode",
];
/// Chinese control labels of the legacy pages.
const PRIVATE_LABELS: &[&str] = &["密码", "口令", "用户名", "验证码", "校验码"];

fn invalid() -> Error {
    Error::new("invalid_input", "invalid physics offline request")
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// A character reference can hide credential vocabulary from a lexical scan,
/// so the reference is removed before the markers are matched again.
fn without_character_references(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'&' {
            if bytes.get(index + 1) == Some(&b'#') {
                let mut end = index + 2;
                let hexadecimal = bytes
                    .get(end)
                    .is_some_and(|byte| matches!(*byte, b'x' | b'X'));
                if hexadecimal {
                    end += 1;
                }
                let first_digit = end;
                while bytes.get(end).is_some_and(|byte| {
                    if hexadecimal {
                        byte.is_ascii_hexdigit()
                    } else {
                        byte.is_ascii_digit()
                    }
                }) {
                    end += 1;
                }
                if end > first_digit && bytes.get(end) == Some(&b';') {
                    index = end + 1;
                    continue;
                }
            } else {
                // The HTML named-entity table has bounded names; numeric
                // references above can instead contain arbitrarily many digits.
                let limit = index.saturating_add(64).min(bytes.len());
                if let Some(offset) = bytes[index..limit].iter().position(|byte| *byte == b';') {
                    let named = std::str::from_utf8(&bytes[index + 1..index + offset + 1])
                        .ok()
                        .and_then(|name| html5ever::data::NAMED_ENTITIES.get(name))
                        .is_some_and(|value| value.0 != 0);
                    if named {
                        index += offset + 1;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// Case-insensitive lexical scan of the supplied bytes. The scan also runs on
/// the bytes with their character references removed, so an entity cannot
/// hide credential vocabulary from the admission check.
fn sensitive_markers_hit(bytes: &[u8]) -> bool {
    if marker_hit(bytes, SENSITIVE_MARKERS) {
        return true;
    }
    if !bytes.contains(&b'&') {
        return false;
    }
    let stripped = without_character_references(bytes);
    marker_hit(&stripped, SENSITIVE_MARKERS)
}

/// Whether the bytes carry a marker, ignoring case.
fn marker_hit(bytes: &[u8], markers: &[&[u8]]) -> bool {
    markers.iter().any(|marker| {
        bytes
            .windows(marker.len())
            .any(|part| part.eq_ignore_ascii_case(marker))
    })
}

/// Structural probe that keeps no value: it reports only whether a JSON
/// document carries credential-like keys or values. Every string it inspects
/// is wiped when it is dropped.
struct JsonPrivacy(bool);

impl<'de> Deserialize<'de> for JsonPrivacy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Probe;
        impl<'de> Visitor<'de> for Probe {
            type Value = JsonPrivacy;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON value")
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(false))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(JsonPrivacy(sensitive_markers_hit(value.as_bytes())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                let value = Zeroizing::new(value);
                Ok(JsonPrivacy(sensitive_markers_hit(value.as_bytes())))
            }
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer
                    .deserialize_any(Probe)
                    .map(|JsonPrivacy(sensitive)| JsonPrivacy(sensitive))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut sensitive = false;
                while let Some(JsonPrivacy(value)) = seq.next_element::<JsonPrivacy>()? {
                    sensitive |= value;
                }
                Ok(JsonPrivacy(sensitive))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut sensitive = false;
                while let Some(key) = map.next_key::<String>()? {
                    let key = Zeroizing::new(key);
                    sensitive |= sensitive_markers_hit(key.as_bytes());
                    sensitive |= map.next_value::<JsonPrivacy>()?.0;
                }
                Ok(JsonPrivacy(sensitive))
            }
        }
        deserializer.deserialize_any(Probe)
    }
}

/// Whether a JSON-shaped body carries credential-like keys or values.
fn json_sensitive(bytes: &[u8]) -> bool {
    let trimmed = bytes.iter().position(|byte| !byte.is_ascii_whitespace());
    if !matches!(
        trimmed.and_then(|index| bytes.get(index)),
        Some(b'{') | Some(b'[')
    ) {
        return false;
    }
    serde_json::from_slice::<JsonPrivacy>(bytes)
        .map(|JsonPrivacy(sensitive)| sensitive)
        .unwrap_or(false)
}

/// A selection identity. Decoding is map-only: a positional sequence is not a
/// selection.
#[derive(Clone, Debug, Serialize)]
struct Selection {
    #[serde(rename = "type")]
    kind: u8,
    eid_prefix: String,
    week: String,
    experiment: String,
    weekday: String,
    period: String,
}

impl<'de> Deserialize<'de> for Selection {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &[
            "type",
            "eid_prefix",
            "week",
            "experiment",
            "weekday",
            "period",
        ];
        struct Probe;
        impl<'de> Visitor<'de> for Probe {
            type Value = Selection;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a selection object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Selection, A::Error> {
                let mut kind: Option<u8> = None;
                let mut eid_prefix: Option<String> = None;
                let mut week: Option<String> = None;
                let mut experiment: Option<String> = None;
                let mut weekday: Option<String> = None;
                let mut period: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            if kind.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("type"));
                            }
                            kind = Some(map.next_value()?);
                        }
                        "eid_prefix" => {
                            if eid_prefix.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("eid_prefix"));
                            }
                            eid_prefix = Some(map.next_value()?);
                        }
                        "week" => {
                            if week.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("week"));
                            }
                            week = Some(map.next_value()?);
                        }
                        "experiment" => {
                            if experiment.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("experiment"));
                            }
                            experiment = Some(map.next_value()?);
                        }
                        "weekday" => {
                            if weekday.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("weekday"));
                            }
                            weekday = Some(map.next_value()?);
                        }
                        "period" => {
                            if period.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("period"));
                            }
                            period = Some(map.next_value()?);
                        }
                        other => {
                            return Err(<A::Error as de::Error>::unknown_field(other, FIELDS));
                        }
                    }
                }
                Ok(Selection {
                    kind: kind.ok_or_else(|| <A::Error as de::Error>::missing_field("type"))?,
                    eid_prefix: eid_prefix
                        .ok_or_else(|| <A::Error as de::Error>::missing_field("eid_prefix"))?,
                    week: week.ok_or_else(|| <A::Error as de::Error>::missing_field("week"))?,
                    experiment: experiment
                        .ok_or_else(|| <A::Error as de::Error>::missing_field("experiment"))?,
                    weekday: weekday
                        .ok_or_else(|| <A::Error as de::Error>::missing_field("weekday"))?,
                    period: period
                        .ok_or_else(|| <A::Error as de::Error>::missing_field("period"))?,
                })
            }
        }
        deserializer.deserialize_map(Probe)
    }
}

impl Selection {
    fn validate(&self) -> Result<(), Error> {
        let digits = |value: &str, length: usize| {
            value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit())
        };
        if self.kind > 1
            || self.eid_prefix.is_empty()
            || self.eid_prefix.len() > 32
            || !self
                .eid_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic())
            || !digits(&self.week, 2)
            || !digits(&self.experiment, 4)
            || !digits(&self.weekday, 1)
            || !matches!(self.period.as_str(), "1" | "2" | "3")
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn preview(&self) -> Value {
        let path = format!(
            "elect.php?type={}&step=3&eid={}{}",
            self.kind, self.eid_prefix, self.week
        );
        let body = format!(
            "Result={}{}{}{}",
            self.experiment, self.week, self.weekday, self.period
        );
        let digest = hash(format!("physics-offline-preview-v2\n{path}\n{body}\n").as_bytes());
        json!({
            "selection": self,
            "method": "POST",
            "relative_path": path,
            "body": body,
            "content_type": "application/x-www-form-urlencoded",
            "preview_digest": digest,
            "executable": false,
            "source": "operator_supplied_selection",
            "service_identity": "unverified",
            "weekday_numbering": "unverified",
            "confirmation_authorizes_network": false,
        })
    }
}

/// The replay kind is a plain string; an object or array is not a kind.
#[derive(Clone, Copy)]
enum ReplayKind {
    Groups,
    Verdict,
}

impl<'de> Deserialize<'de> for ReplayKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Probe;
        impl<'de> Visitor<'de> for Probe {
            type Value = ReplayKind;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("\"groups\" or \"verdict\"")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "groups" => Ok(ReplayKind::Groups),
                    "verdict" => Ok(ReplayKind::Verdict),
                    other => Err(<E as de::Error>::unknown_variant(
                        other,
                        &["groups", "verdict"],
                    )),
                }
            }
        }
        deserializer.deserialize_str(Probe)
    }
}

/// A request envelope. Decoding is map-only, and an unknown field is refused
/// at its key, so a rejected credential value is never materialized.
struct Request {
    operation: String,
    action: String,
    selection: Option<Selection>,
    kind: Option<ReplayKind>,
    content_type: Option<String>,
    data: Option<String>,
    has_selection: bool,
    has_kind: bool,
    has_content_type: bool,
    has_data: bool,
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &[
            "operation",
            "action",
            "selection",
            "kind",
            "content_type",
            "data",
        ];
        struct Probe;
        impl<'de> Visitor<'de> for Probe {
            type Value = Request;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a physics request object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Request, A::Error> {
                let mut operation: Option<String> = None;
                let mut action: Option<String> = None;
                let mut selection: Option<Selection> = None;
                let mut kind: Option<ReplayKind> = None;
                let mut content_type: Option<String> = None;
                let mut data: Option<String> = None;
                let mut has_selection = false;
                let mut has_kind = false;
                let mut has_content_type = false;
                let mut has_data = false;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "operation" => {
                            if operation.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("operation"));
                            }
                            operation = Some(map.next_value()?);
                        }
                        "action" => {
                            if action.is_some() {
                                return Err(<A::Error as de::Error>::duplicate_field("action"));
                            }
                            action = Some(map.next_value()?);
                        }
                        "selection" => {
                            if has_selection {
                                return Err(<A::Error as de::Error>::duplicate_field("selection"));
                            }
                            has_selection = true;
                            selection = map.next_value::<Option<Selection>>()?;
                        }
                        "kind" => {
                            if has_kind {
                                return Err(<A::Error as de::Error>::duplicate_field("kind"));
                            }
                            has_kind = true;
                            kind = map.next_value::<Option<ReplayKind>>()?;
                        }
                        "content_type" => {
                            if has_content_type {
                                return Err(<A::Error as de::Error>::duplicate_field(
                                    "content_type",
                                ));
                            }
                            has_content_type = true;
                            content_type = map.next_value::<Option<String>>()?;
                        }
                        "data" => {
                            if has_data {
                                return Err(<A::Error as de::Error>::duplicate_field("data"));
                            }
                            has_data = true;
                            data = map.next_value::<Option<String>>()?;
                        }
                        other => {
                            return Err(<A::Error as de::Error>::unknown_field(other, FIELDS));
                        }
                    }
                }
                Ok(Request {
                    operation: operation
                        .ok_or_else(|| <A::Error as de::Error>::missing_field("operation"))?,
                    action: action
                        .ok_or_else(|| <A::Error as de::Error>::missing_field("action"))?,
                    selection,
                    kind,
                    content_type,
                    data,
                    has_selection,
                    has_kind,
                    has_content_type,
                    has_data,
                })
            }
        }
        deserializer.deserialize_map(Probe)
    }
}

impl Request {
    /// Refuse any field the selected action does not define, including a
    /// field that was supplied with a null value.
    fn allow_only(&self, allowed: &[&str]) -> Result<(), Error> {
        let refused = (self.has_selection && !allowed.contains(&"selection"))
            || (self.has_kind && !allowed.contains(&"kind"))
            || (self.has_content_type && !allowed.contains(&"content_type"))
            || (self.has_data && !allowed.contains(&"data"));
        if refused {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Active document text for business parsing. Inline markup keeps its
/// adjacency, so a number split across inline elements stays one number,
/// while a block-level boundary ends the run and a following digit is then
/// ambiguous.
fn rendered_text(document: &Html) -> String {
    fn walk(node: NodeRef<'_, Node>, out: &mut String) {
        for child in node.children() {
            match child.value() {
                Node::Text(text) => out.push_str(&text.text),
                Node::Element(element) => {
                    let Some(reference) = ElementRef::wrap(child) else {
                        continue;
                    };
                    if crate::html::is_inert_context(reference) || element.name() == "head" {
                        continue;
                    }
                    let inline = crate::html::is_html_element(reference)
                        && INLINE_ELEMENTS.contains(&element.name());
                    if !inline {
                        out.push('\n');
                    }
                    // Replaced widgets do not render their fallback as ordinary
                    // inline prose. Keep the boundary without letting that text
                    // conceal a numeric continuation on the other side.
                    if !(crate::html::is_html_element(reference)
                        && matches!(element.name(), "progress" | "meter"))
                    {
                        walk(child, out);
                    }
                    if !inline {
                        out.push('\n');
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = String::new();
    walk(*document.root_element(), &mut out);
    out
}

/// Privacy projection of the whole document. Every text node, including
/// inactive subtrees and template fragments, is joined without whitespace, so
/// a private label cannot hide behind inline markup, an inactive container or
/// spacing. This projection is private to the privacy path; the business
/// projection keeps its own boundaries.
fn privacy_text(document: &Html, exclude_fallback: bool) -> String {
    let mut out = String::new();
    for node in document.tree.root().descendants() {
        if exclude_fallback && in_fallback(node) {
            continue;
        }
        if let Node::Text(text) = node.value() {
            out.extend(
                text.text
                    .chars()
                    .filter(|character| !character.is_whitespace()),
            );
        }
    }
    out
}

fn private_label_hit(value: &str) -> bool {
    PRIVATE_LABELS.iter().any(|marker| value.contains(*marker))
}

/// Match the already-decoded DOM literally. A literal ampersand here may
/// itself have come from `&amp;`; interpreting it a second time is wrong.
fn private_vocabulary_hit(text: &str) -> bool {
    marker_hit(text.as_bytes(), SENSITIVE_MARKERS)
        || marker_hit(text.as_bytes(), CHALLENGE_PRIVACY_MARKERS)
        || private_label_hit(text)
}

/// Privacy admission over the whole document, independent of whether a
/// control can currently be interacted with. An inactive or hidden control
/// can still carry a value, and its markup can split a private label.
fn document_privacy_hit(document: &Html, exclude_fallback: bool) -> bool {
    let projection = Zeroizing::new(privacy_text(document, exclude_fallback));
    if private_vocabulary_hit(&projection) {
        return true;
    }
    for node in document.tree.root().descendants() {
        if exclude_fallback && in_fallback(node) {
            continue;
        }
        let Node::Element(element) = node.value() else {
            continue;
        };
        for (name, value) in element.attrs() {
            // An attribute name and its value can each carry a marker, and a
            // control can split one marker across the two.
            let joined: String = name
                .chars()
                .chain(value.chars())
                .filter(|character| !character.is_whitespace())
                .collect();
            if private_vocabulary_hit(&joined) {
                return true;
            }
        }
    }
    false
}

// Each source ampersand is marked in a second, bounded native parse. The
// markers do not stand in for HTML syntax: html5ever still decides whether a
// reference was consumed in its actual data, attribute or raw-text context.
// The unmarked tree must equal the original tree before this observation can
// authorize disclosure. Excessive or ambiguous observations fail closed.
const MAX_PROVENANCE_REFERENCES: usize = 4096;
const PROVENANCE_MARKER_DIGITS: usize = 4;
const MAX_PROVENANCE_BYTES: usize = 1024 * 1024;

enum ReferenceKind<'a> {
    None,
    Numeric {
        tail: &'a str,
    },
    Named {
        tail: &'a str,
        first: char,
        second: Option<char>,
    },
}

struct SourceReference<'a> {
    raw: &'a str,
    kind: ReferenceKind<'a>,
}

impl<'a> SourceReference<'a> {
    fn new(raw: &'a str) -> Self {
        let bytes = raw.as_bytes();
        let kind = if bytes.get(1) == Some(&b'#') {
            let mut end = 2;
            let hex = bytes
                .get(end)
                .is_some_and(|byte| matches!(*byte, b'x' | b'X'));
            if hex {
                end += 1;
            }
            let first = end;
            while bytes.get(end).is_some_and(|byte| {
                if hex {
                    byte.is_ascii_hexdigit()
                } else {
                    byte.is_ascii_digit()
                }
            }) {
                end += 1;
            }
            if end == first {
                ReferenceKind::None
            } else {
                if bytes.get(end) == Some(&b';') {
                    end += 1;
                }
                ReferenceKind::Numeric { tail: &raw[end..] }
            }
        } else {
            // html5ever's own table contains both complete names and their
            // prefixes. Named references are bounded; numeric ones are not.
            let mut longest = None;
            for end in 1..=bytes.len().saturating_sub(1).min(64) {
                let Some(&(first, second)) = html5ever::data::NAMED_ENTITIES.get(&raw[1..=end])
                else {
                    break;
                };
                if first != 0 {
                    longest = Some((end, first, second));
                }
            }
            match longest.and_then(|(end, first, second)| {
                Some((
                    end,
                    char::from_u32(first)?,
                    if second == 0 {
                        None
                    } else {
                        Some(char::from_u32(second)?)
                    },
                ))
            }) {
                Some((end, first, second)) => ReferenceKind::Named {
                    tail: &raw[1 + end..],
                    first,
                    second,
                },
                None => ReferenceKind::None,
            }
        };
        Self { raw, kind }
    }

    /// Return the parser-produced reference characters and untouched tail,
    /// but only when both agree exactly with this source candidate. A literal
    /// candidate is not a reference, even if it resembles a name.
    fn consumed<'b>(&self, parsed: &'b str) -> Result<Option<(&'b str, &'b str)>, ()> {
        if parsed == self.raw {
            return Ok(None);
        }
        let (tail, expected) = match &self.kind {
            ReferenceKind::None => return Err(()),
            ReferenceKind::Numeric { tail } => (*tail, None),
            ReferenceKind::Named {
                tail,
                first,
                second,
            } => (*tail, Some((*first, *second))),
        };
        let prefix = parsed.strip_suffix(tail).ok_or(())?;
        let mut chars = prefix.chars();
        let first = chars.next().ok_or(())?;
        if let Some((expected_first, expected_second)) = expected {
            if first != expected_first || chars.next() != expected_second || chars.next().is_some()
            {
                return Err(());
            }
        } else if chars.next().is_some() {
            return Err(());
        }
        Ok(Some((prefix, &parsed[prefix.len()..])))
    }
}

fn provenance_marker(source: &str, document: &Html) -> Option<char> {
    // A source-absent private-use scalar is neutral HTML text, not a tag,
    // attribute delimiter, whitespace, or a case-folded ASCII character.
    let mut used = [false; 0x1900];
    let mut record = |value: &str| {
        for character in value.chars() {
            let value = character as u32;
            if (0xe000..=0xf8ff).contains(&value) {
                used[(value - 0xe000) as usize] = true;
            }
        }
    };
    record(source);
    // The source can encode a private-use scalar as a reference. Check the
    // actual decoded DOM too; a collision is never used as an annotation.
    for node in document.tree.root().descendants() {
        match node.value() {
            Node::Text(text) => record(&text.text),
            Node::Element(element) => {
                record(element.name.local.as_ref());
                for (name, value) in element.attrs.iter() {
                    record(name.local.as_ref());
                    record(value.as_ref());
                }
            }
            Node::Comment(comment) => record(&comment.comment),
            Node::Doctype(doctype) => {
                record(&doctype.name);
                record(&doctype.public_id);
                record(&doctype.system_id);
            }
            Node::ProcessingInstruction(pi) => {
                record(&pi.target);
                record(&pi.data);
            }
            Node::Document | Node::Fragment => {}
        }
    }
    used.iter()
        .position(|present| !present)
        .and_then(|index| char::from_u32(0xe000 + index as u32))
}

fn marked_source(
    source: &str,
    marker: char,
) -> Result<(Zeroizing<String>, Vec<SourceReference<'_>>), ()> {
    let bytes = source.as_bytes();
    let mut marked = Zeroizing::new(String::with_capacity(source.len()));
    let mut references = Vec::new();
    let mut copied = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] != b'&' {
            cursor += 1;
            continue;
        }
        if references.len() == MAX_PROVENANCE_REFERENCES {
            return Err(());
        }
        let start = cursor;
        cursor += 1;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'#')
        {
            cursor += 1;
        }
        // Keep '=' in the observation: a semicolonless named reference in an
        // attribute is not consumed when followed by '=' or an ASCII letter
        // or digit. The full alphanumeric run keeps that native lookahead.
        if bytes
            .get(cursor)
            .is_some_and(|byte| matches!(*byte, b';' | b'='))
        {
            cursor += 1;
        }
        marked.push_str(&source[copied..start]);
        let id = references.len();
        write!(&mut *marked, "{marker}{id:04}{marker}").map_err(|_| ())?;
        marked.push_str(&source[start..cursor]);
        write!(&mut *marked, "{marker}{id:04}{marker}").map_err(|_| ())?;
        references.push(SourceReference::new(&source[start..cursor]));
        copied = cursor;
    }
    marked.push_str(&source[copied..]);
    Ok((marked, references))
}

fn take_provenance_marker<'a>(
    value: &'a str,
    marker: char,
    counts: &mut [u8],
) -> Result<(usize, &'a str), ()> {
    let value = value.strip_prefix(marker).ok_or(())?;
    let digits = value.as_bytes().get(..PROVENANCE_MARKER_DIGITS).ok_or(())?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    let id = digits
        .iter()
        .fold(0usize, |id, digit| id * 10 + usize::from(digit - b'0'));
    let rest = value[PROVENANCE_MARKER_DIGITS..]
        .strip_prefix(marker)
        .ok_or(())?;
    let count = counts.get_mut(id).ok_or(())?;
    if *count == 2 {
        return Err(());
    }
    *count += 1;
    Ok((id, rest))
}

/// Remove annotations from a native value without interpreting that value as
/// HTML. Used for tree identity, tag names, comments and attribute names.
fn unmark(value: &str, marker: char, counts: &mut [u8]) -> Result<Zeroizing<String>, ()> {
    let mut result = Zeroizing::new(String::with_capacity(value.len()));
    let mut rest = value;
    while let Some(index) = rest.find(marker) {
        result.push_str(&rest[..index]);
        let (_, after) = take_provenance_marker(&rest[index..], marker, counts)?;
        rest = after;
    }
    result.push_str(rest);
    Ok(result)
}

/// Return both the unchanged native value and a privacy-only stream. In the
/// latter, a pair of marker scalars brackets each *consumed* reference output;
/// the matcher can either retain or omit that whole output. This also covers
/// a marker assembled from some decoded references and other omitted ones.
fn provenance_value(
    value: &str,
    marker: char,
    references: &[SourceReference<'_>],
    counts: &mut [u8],
) -> Result<(Zeroizing<String>, Zeroizing<String>), ()> {
    let mut clean = Zeroizing::new(String::with_capacity(value.len()));
    let mut projected = Zeroizing::new(String::with_capacity(value.len()));
    let mut rest = value;
    while let Some(start) = rest.find(marker) {
        clean.push_str(&rest[..start]);
        projected.push_str(&rest[..start]);
        let (id, after_open) = take_provenance_marker(&rest[start..], marker, counts)?;
        let end = after_open.find(marker).ok_or(())?;
        let parsed = &after_open[..end];
        let (closing_id, after_close) = take_provenance_marker(&after_open[end..], marker, counts)?;
        if id != closing_id {
            return Err(());
        }
        let reference = references.get(id).ok_or(())?;
        clean.push_str(parsed);
        if let Some((decoded, tail)) = reference.consumed(parsed)? {
            projected.push(marker);
            projected.push_str(decoded);
            projected.push(marker);
            projected.push_str(tail);
        } else {
            projected.push_str(parsed);
        }
        rest = after_close;
    }
    clean.push_str(rest);
    projected.push_str(rest);
    Ok((clean, projected))
}

struct PrivacyPattern {
    masks: [u64; 256],
    state: u64,
    saved: u64,
    accept: u64,
}

/// A bounded streaming NFA. For a consumed reference both its actual decoded
/// output and its omission remain possible; all other DOM characters are
/// literal. Unlike trying all subsets, its cost is linear in document size.
struct PrivacyMatcher {
    patterns: Vec<PrivacyPattern>,
    hit: bool,
}

impl PrivacyMatcher {
    fn new() -> Self {
        let patterns = SENSITIVE_MARKERS
            .iter()
            .chain(CHALLENGE_PRIVACY_MARKERS.iter())
            .copied()
            .chain(PRIVATE_LABELS.iter().map(|label| label.as_bytes()))
            .map(|pattern| {
                let mut masks = [0u64; 256];
                for (index, byte) in pattern.iter().copied().enumerate() {
                    let bit = 1u64 << (index + 1);
                    masks[byte.to_ascii_lowercase() as usize] |= bit;
                    masks[byte.to_ascii_uppercase() as usize] |= bit;
                }
                PrivacyPattern {
                    masks,
                    state: 1,
                    saved: 0,
                    accept: 1u64 << pattern.len(),
                }
            })
            .collect();
        Self {
            patterns,
            hit: false,
        }
    }

    fn reset(&mut self) {
        for pattern in &mut self.patterns {
            pattern.state = 1;
        }
        self.hit = false;
    }

    fn feed_character(&mut self, character: char) {
        if character.is_whitespace() { return; }
        let mut buffer = [0; 4];
        for byte in character.encode_utf8(&mut buffer).bytes() {
            for pattern in &mut self.patterns {
                pattern.state = ((pattern.state << 1) & pattern.masks[byte as usize]) | 1;
                self.hit |= pattern.state & pattern.accept != 0;
            }
        }
    }

    fn feed_literal(&mut self, value: &str) {
        for character in value.chars() { self.feed_character(character); }
    }

    fn feed(&mut self, value: &str, marker: char) -> Result<(), ()> {
        let mut optional = false;
        for character in value.chars() {
            if character == marker {
                if optional {
                    for pattern in &mut self.patterns {
                        pattern.state |= pattern.saved;
                    }
                } else {
                    for pattern in &mut self.patterns {
                        pattern.saved = pattern.state;
                    }
                }
                optional = !optional;
            } else {
                self.feed_character(character);
            }
        }
        if optional {
            return Err(());
        }
        Ok(())
    }
}

struct SourceAttribute {
    name: QualName,
    value: Zeroizing<String>,
}

struct SourcePrivacy {
    text: Zeroizing<String>,
    text_matcher: PrivacyMatcher,
    attribute_matcher: PrivacyMatcher,
    attributes: Vec<SourceAttribute>,
    sensitive: bool,
    unreviewed: bool,
}

impl SourcePrivacy {
    fn new() -> Self {
        Self { text: Zeroizing::new(String::new()), text_matcher: PrivacyMatcher::new(),
            attribute_matcher: PrivacyMatcher::new(), attributes: Vec::new(),
            sensitive: false, unreviewed: false }
    }

    fn observe(&mut self, token: &Token) {
        match token {
            Token::CharacterTokens(text) => {
                self.text.extend(text.chars().filter(|character| !character.is_whitespace()));
                self.text_matcher.feed_literal(text);
            }
            Token::TagToken(tag) if tag.kind == TagKind::StartTag => {
                for attribute in &tag.attrs {
                    if tag.name.as_ref().eq_ignore_ascii_case("iframe")
                        && attribute.name.local.as_ref().eq_ignore_ascii_case("srcdoc")
                    {
                        // Nested HTML is not admitted by the outer document's
                        // parser, even if the iframe is currently inert.
                        self.unreviewed = true;
                    }
                    self.attribute_matcher.reset();
                    self.attribute_matcher.feed_literal(attribute.name.local.as_ref());
                    self.attribute_matcher.feed_literal(attribute.value.as_ref());
                    self.sensitive |= self.attribute_matcher.hit;
                    self.attributes.push(SourceAttribute { name: attribute.name.clone(),
                        value: Zeroizing::new(attribute.value.to_string()) });
                }
            }
            Token::CommentToken(text) => {
                self.attribute_matcher.reset();
                self.attribute_matcher.feed_literal(text);
                self.sensitive |= self.attribute_matcher.hit;
            }
            Token::DoctypeToken(doctype) => {
                for value in [doctype.name.as_deref(), doctype.public_id.as_deref(), doctype.system_id.as_deref()].into_iter().flatten() {
                    self.attribute_matcher.reset();
                    self.attribute_matcher.feed_literal(value);
                    self.sensitive |= self.attribute_matcher.hit;
                }
            }
            Token::NullCharacterToken => self.unreviewed = true,
            Token::ParseError(error) => {
                // These character-reference errors preserve an inspectable
                // literal or decoded token. Other tokenizer repairs, including
                // duplicate attributes and unfinished tags, need review.
                if !matches!(error.as_ref(),
                    "Semicolon missing after numeric character reference"
                    | "Numeric character reference without digits"
                    | "Invalid numeric character reference"
                    | "Invalid character reference"
                    | "Character reference does not end with semicolon")
                { self.unreviewed = true; }
            }
            _ => {}
        }
    }

    fn reason(mut self, document: &Html) -> Option<&'static str> {
        if self.sensitive || self.text_matcher.hit { return Some("sensitive_response_material"); }
        if self.unreviewed { return Some("response_safety_unreviewed"); }
        let text = Zeroizing::new(privacy_text(document, false));
        if self.text.as_str() != text.as_str() { return Some("response_safety_unreviewed"); }
        let mut observed = Vec::new();
        for node in document.tree.root().descendants() {
            let Node::Element(element) = node.value() else { continue };
            for (name, value) in element.attrs.iter() {
                observed.push(SourceAttribute { name: name.clone(), value: Zeroizing::new(value.to_string()) });
            }
        }
        let compare = |a: &SourceAttribute, b: &SourceAttribute| {
            a.name.cmp(&b.name).then_with(|| a.value.as_str().cmp(b.value.as_str()))
        };
        self.attributes.sort_unstable_by(compare);
        observed.sort_unstable_by(compare);
        if self.attributes.len() != observed.len()
            || self.attributes.iter().zip(&observed).any(|(a, b)| compare(a, b) != std::cmp::Ordering::Equal)
        { return Some("response_safety_unreviewed"); }
        None
    }
}

/// Compare the complete annotated tree with the original, then inspect only
/// the annotated native text and attribute values. Any changed topology,
/// attribute, token boundary, marker collision or exhausted bound is not a
/// privacy clearance. Comments and doctypes participate in tree equality but
/// are not reinterpreted as text or controls.
fn reference_privacy_hit(
    source: &str,
    original: &Html,
    exclude_fallback: bool,
) -> Result<bool, ()> {
    use ego_tree::iter::Edge;

    if !source.as_bytes().contains(&b'&') {
        return Ok(false);
    }
    if source.len() > MAX_PROVENANCE_BYTES {
        return Err(());
    }
    let marker = provenance_marker(source, original).ok_or(())?;
    let (marked, references) = marked_source(source, marker)?;
    if marked.len() > MAX_PROVENANCE_BYTES {
        return Err(());
    }
    let mut counts = vec![0u8; references.len()];
    // Apply the existing native source/token/tree budgets to the annotated
    // parse too, before allowing a second complete tree to be constructed.
    if assess_challenge_body(marked.as_bytes(), Some("text/html; charset=utf-8"), true)
        != ChallengeAssessment::Clear
    {
        return Err(());
    }
    let observed = Html::parse_document(&marked);
    if original.quirks_mode != observed.quirks_mode {
        return Err(());
    }

    let mut left = original.tree.root().traverse();
    let mut right = observed.tree.root().traverse();
    let mut text_matcher = PrivacyMatcher::new();
    let mut attribute_matcher = PrivacyMatcher::new();
    let mut attribute_hit = false;
    loop {
        match (left.next(), right.next()) {
            (None, None) => break,
            (Some(Edge::Close(_)), Some(Edge::Close(_))) => {}
            (Some(Edge::Open(a)), Some(Edge::Open(b))) => match (a.value(), b.value()) {
                (Node::Document, Node::Document) | (Node::Fragment, Node::Fragment) => {}
                (Node::Text(a_text), Node::Text(b_text)) => {
                    let (clean, projected) =
                        provenance_value(&b_text.text, marker, &references, &mut counts)?;
                    if a_text.text.as_ref() != clean.as_str() {
                        return Err(());
                    }
                    if !(exclude_fallback && in_fallback(a)) {
                        text_matcher.feed(&projected, marker)?;
                    }
                }
                (Node::Element(a_element), Node::Element(b_element)) => {
                    let name = unmark(b_element.name.local.as_ref(), marker, &mut counts)?;
                    if a_element.name.ns != b_element.name.ns
                        || a_element.name.prefix != b_element.name.prefix
                        || a_element.name.local.as_ref() != name.as_str()
                    {
                        return Err(());
                    }
                    // Match complete qualified names independently of DOM
                    // attribute order; every original must be removed once.
                    let mut attributes = std::collections::HashMap::with_capacity(a_element.attrs.len());
                    for (name, value) in a_element.attrs.iter() {
                        if attributes.insert(name.clone(), value.as_ref()).is_some() { return Err(()); }
                    }
                    for (name, value) in b_element.attrs.iter() {
                        let local = unmark(name.local.as_ref(), marker, &mut counts)?;
                        let mut key = name.clone();
                        key.local = local.as_str().into();
                        let expected = attributes.remove(&key).ok_or(())?;
                        let (clean, projected) =
                            provenance_value(value.as_ref(), marker, &references, &mut counts)?;
                        if expected != clean.as_str() {
                            return Err(());
                        }
                        if !(exclude_fallback && in_fallback(a)) {
                            attribute_matcher.reset();
                            attribute_matcher.feed(&local, marker)?;
                            attribute_matcher.feed(&projected, marker)?;
                            attribute_hit |= attribute_matcher.hit;
                        }
                    }
                    if !attributes.is_empty() {
                        return Err(());
                    }
                }
                (Node::Comment(a_comment), Node::Comment(b_comment)) => {
                    if a_comment.comment.as_ref()
                        != unmark(&b_comment.comment, marker, &mut counts)?.as_str()
                    {
                        return Err(());
                    }
                }
                (Node::Doctype(a_doctype), Node::Doctype(b_doctype)) => {
                    if a_doctype.name.as_ref()
                        != unmark(&b_doctype.name, marker, &mut counts)?.as_str()
                        || a_doctype.public_id.as_ref()
                            != unmark(&b_doctype.public_id, marker, &mut counts)?.as_str()
                        || a_doctype.system_id.as_ref()
                            != unmark(&b_doctype.system_id, marker, &mut counts)?.as_str()
                    {
                        return Err(());
                    }
                }
                (Node::ProcessingInstruction(a_pi), Node::ProcessingInstruction(b_pi)) => {
                    if a_pi.target.as_ref() != unmark(&b_pi.target, marker, &mut counts)?.as_str()
                        || a_pi.data.as_ref() != unmark(&b_pi.data, marker, &mut counts)?.as_str()
                    {
                        return Err(());
                    }
                }
                _ => return Err(()),
            },
            _ => return Err(()),
        }
    }
    if counts.iter().any(|count| *count != 2) {
        return Err(());
    }
    Ok(text_matcher.hit || attribute_hit)
}

/// Whether a node belongs to HTML noscript fallback rather than reviewed DOM.
fn in_fallback(node: NodeRef<'_, Node>) -> bool {
    std::iter::once(node).chain(node.ancestors()).any(|node| {
        ElementRef::wrap(node).is_some_and(|element| {
            crate::html::is_html_element(element) && element.value().name() == "noscript"
        })
    })
}

/// Whether the document holds fallback markup this parser cannot review.
/// A scripting-enabled parse keeps a noscript body as raw text, so the
/// controls inside it are never inspected and their privacy is unconfirmed.
fn unreviewable_fallback_present(document: &Html) -> bool {
    document.tree.root().descendants().any(|node| {
        let Some(element) = ElementRef::wrap(node) else {
            return false;
        };
        if !crate::html::is_html_element(element)
            || !element.value().name().eq_ignore_ascii_case("noscript")
        {
            return false;
        }
        element.text().any(|text| !text.trim().is_empty())
    })
}

/// Why the fixture must not be disclosed. Privacy is decided independently of
/// whether a challenge control can currently be interacted with: an inactive
/// control still carries data, and its markup can split a private label.
fn privacy_reason(
    bytes: &[u8],
    text: Option<&str>,
    document: Option<&Html>,
) -> Option<&'static str> {
    // Fallback markup is never parsed as controls, so its privacy is
    // unconfirmed even when its text carries no vocabulary.
    if document.is_some_and(unreviewable_fallback_present) {
        let document = document.unwrap();
        // Establish reasons from reviewed nodes, not raw noscript payloads.
        // The latter must retain the fallback-only unreviewed classification.
        if text.is_some_and(|text| {
            assess_challenge_body(text.as_bytes(), Some("text/html; charset=utf-8"), true)
                == ChallengeAssessment::Detected
        }) {
            return Some("challenge_detected");
        }
        if document_privacy_hit(document, true) {
            return Some("sensitive_response_material");
        }
        if text.is_some_and(|text| reference_privacy_hit(text, document, true) == Ok(true)) {
            return Some("sensitive_response_material");
        }
        return Some("response_safety_unreviewed");
    }
    // The original bytes are screened as they were supplied, so a credential
    // in an unstructured body cannot hide from the admission check. HTML
    // reference syntax is not stripped here: raw text and attributes have
    // different native consumption rules.
    if marker_hit(bytes, SENSITIVE_MARKERS) || json_sensitive(bytes)
        || text.is_some_and(private_label_hit) {
        return Some("sensitive_response_material");
    }
    let (Some(text), Some(document)) = (text, document) else {
        // A fixture that cannot be decoded cannot be reviewed at all.
        return Some(if sensitive_markers_hit(bytes) {
            "sensitive_response_material"
        } else {
            "response_safety_unreviewed"
        });
    };
    // The shared assessment decides whether a challenge is interactive.
    match assess_challenge_body(text.as_bytes(), Some("text/html; charset=utf-8"), true) {
        ChallengeAssessment::Detected => return Some("challenge_detected"),
        ChallengeAssessment::Unreviewed => return Some("response_safety_unreviewed"),
        ChallengeAssessment::Clear => {}
    }
    // Private vocabulary is screened in the decoded document, so an inactive
    // control, an escaped name or a label split by inline markup cannot
    // disclose anything.
    if document_privacy_hit(document, false) {
        return Some("sensitive_response_material");
    }
    match reference_privacy_hit(text, document, false) {
        Ok(true) => return Some("sensitive_response_material"),
        Err(()) => return Some("response_safety_unreviewed"),
        Ok(false) => {}
    }
    None
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Group {
    group_code: String,
    remaining_seats: u32,
}

/// Verdict markers of the legacy selection page. Exactly one marker may be
/// present; two markers in one body are ambiguous.
fn classify_verdict(text: &str) -> Option<&'static str> {
    const MARKERS: [(&str, &str); 6] = [
        ("恭喜你，选课成功！", "success_marker"),
        ("该组已经选满。请重试！", "full"),
        ("此题目在这个时间段没有开放", "not_open"),
        ("三天内课表已冻结，请换个时间段!", "frozen"),
        ("还没做吧？！", "prerequisite_incomplete"),
        ("你还没有登录，无权访问。", "session_invalid"),
    ];
    let mut found: Option<&'static str> = None;
    for (marker, verdict) in MARKERS {
        if text.contains(marker) {
            if found.is_some() {
                return None;
            }
            found = Some(verdict);
        }
    }
    found
}

/// Seat count of one group. A count that continues in a later field is
/// ambiguous and is refused instead of being truncated.
fn parse_remaining_seats(text: &str) -> Result<u32, &'static str> {
    let trimmed = text.trim_start();
    let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err("invalid_remaining_seats");
    }
    let value: u32 = trimmed[..digits]
        .parse()
        .map_err(|_| "invalid_remaining_seats")?;
    let rest = &trimmed[digits..];
    if rest
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric())
    {
        return Err("invalid_remaining_seats");
    }
    let following = rest.trim_start();
    if following.as_bytes().first().is_some_and(u8::is_ascii_digit)
        || following.chars().next().is_some_and(|separator| {
            matches!(separator, '.' | ',' | '．' | '，')
                && following[separator.len_utf8()..]
                    .trim_start()
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_digit)
        })
    {
        return Err("ambiguous_remaining_seats");
    }
    Ok(value)
}

/// Group listing of one options page. Codes and counts must appear in order,
/// and no orphaned or duplicated label may be present.
fn parse_groups(text: &str) -> Result<Vec<Group>, &'static str> {
    let mut cursor = 0usize;
    let mut groups: Vec<Group> = Vec::new();
    while let Some(relative) = text[cursor..].find(CODE_LABEL) {
        let label_at = cursor + relative;
        if text[cursor..label_at].contains(SEATS_LABEL) {
            return Err("orphan_seat_label");
        }
        let start = label_at + CODE_LABEL.len();
        let Some(seats_relative) = text[start..].find(SEATS_LABEL) else {
            return Err("missing_seat_label");
        };
        let seats_at = start + seats_relative;
        if text[start..seats_at].contains(CODE_LABEL) {
            return Err("ambiguous_group_labels");
        }
        let code = text[start..seats_at]
            .split_whitespace()
            .next()
            .ok_or("missing_group_code")?;
        if code.is_empty() || code.len() > 128 || code.chars().any(char::is_control) {
            return Err("invalid_group_code");
        }
        let after = seats_at + SEATS_LABEL.len();
        let remaining_seats = parse_remaining_seats(&text[after..])?;
        groups.push(Group {
            group_code: code.to_owned(),
            remaining_seats,
        });
        if groups.len() > 4096 {
            return Err("too_many_groups");
        }
        cursor = after;
    }
    if groups.is_empty() || text[cursor..].contains(SEATS_LABEL) {
        return Err("unrecognized_group_listing");
    }
    Ok(groups)
}

/// Retain only a known media type, not arbitrary parameters that may be private.
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

/// Evidence about the operator-supplied original bytes. Only a body that
/// carries no credential, session or challenge material is echoed back.
fn evidence(bytes: &[u8], content_type: Option<&str>, reason: Option<&str>) -> Value {
    json!({
        "source": "operator_supplied_response_bytes",
        "encoding": "base64",
        "content_type": safe_mime(content_type),
        "byte_length": bytes.len(),
        "sha256": hash(bytes),
        "data": reason.is_none().then(|| STANDARD.encode(bytes)),
        "raw_withheld": reason.is_some(),
        "raw_withheld_reason": reason,
    })
}

fn reference_blocker() -> Value {
    json!({
        "schema_version": 1,
        "type": "physics_reference",
        "result": "unsupported",
        "source_candidate": {
            "origin": "https://gitee.com/PhisicsExperiment/PhysicsExperiment",
            "commit": "658a981f6425ff1cd1bc213caa3cb2c7036e4f64",
            "tree": "828b8f793f373cb34fb839ca9040f3ed700b78d5",
            "status": "research_identity_only_not_locally_verified_inventory",
        },
        "reason": "The pinned public repository contains Preview.pdf candidates, but its root MIT software/documentation license does not establish per-PDF or third-party-text rights. Some reports may contain assessment answers. No item has documented rights and assessment admission or locally verified complete tree/blob SHA and byte length; catalog and retrieval are unavailable.",
        "required_admission": [
            "complete pinned tree and blob identity verification",
            "per-item documented rights covering original bytes",
            "per-item assessment-content admission",
            "source-owned selectors and origins",
            "cache-first exact original bytes",
            "shared-governor single-request transport",
        ],
        "gitee_envelope_notes": {
            "blob": "base64 content inside JSON, not raw PDF bytes",
            "directory": {"mode": "40000", "size": 0},
        },
        "rights_review_required": true,
        "assessment_review_required": true,
        "inventory_verified": false,
        "network_request_performed": false,
        "requests_sent": 0,
    })
}

fn unsupported() -> Value {
    json!({
        "schema_version": 1,
        "type": "physics_experiment",
        "result": "unsupported",
        "reason": "Authentication, captcha, session operations, selection and withdrawal have no independently admitted service contract in this adapter. No service-equivalence probe, transport, private state or governor mutation is implemented. Offline previews do not authorize submission.",
        "network_request_performed": false,
        "requests_sent": 0,
        "confirmation_available": false,
    })
}

fn capability() -> Value {
    json!({
        "schema_version": 1,
        "type": "physics_experiment",
        "result": "capability",
        "online_execution_enabled": false,
        "support": ["offline_selection_preview", "operator_fixture_html_replay"],
        "authentication": "unsupported",
        "selection_submission": "unsupported",
        "reference": reference_blocker(),
        "network_request_performed": false,
        "requests_sent": 0,
    })
}

/// Replay of operator-supplied fixture bytes.
fn replay(kind: ReplayKind, data: &str, content_type: Option<&str>) -> Result<Value, Error> {
    let bytes = STANDARD.decode(data).map_err(|_| invalid())?;
    if bytes.len() > MAX_BODY {
        return Err(invalid());
    }
    let decoded = decode_html(&bytes, content_type);
    let mut output = json!({
        "schema_version": 1,
        "type": "physics_experiment_replay",
        "source": "operator_supplied_response_bytes",
        "online_acceptance": false,
        "enrollment_verified": false,
        "network_request_performed": false,
    });
    match decoded {
        Ok(text) => {
            let mut source = SourcePrivacy::new();
            let document = crate::html::bounded_html_with_tokens(&text, |token| source.observe(token));
            let reason = match &document {
                Ok(document) => privacy_reason(&bytes, Some(&text), Some(document))
                    .or_else(|| source.reason(document)),
                Err(()) => {
                    let reason = privacy_reason(&bytes, Some(&text), None);
                    if reason == Some("response_safety_unreviewed")
                        && assess_challenge_body(text.as_bytes(), Some("text/html; charset=utf-8"), true) == ChallengeAssessment::Detected
                    { Some("challenge_detected") } else { reason }
                }
            };
            if reason.is_none() {
                let active_text = Zeroizing::new(rendered_text(document.as_ref().expect("clear source has a complete document")));
                let parsed = match kind {
                    ReplayKind::Groups => {
                        parse_groups(active_text.as_str()).map(|groups| json!({"groups": groups}))
                    }
                    ReplayKind::Verdict => classify_verdict(active_text.as_str())
                        .map(|verdict| json!({"verdict": verdict}))
                        .ok_or("unrecognized_selection_response"),
                };
                match parsed {
                    Ok(data) => {
                        output["result"] = json!("parsed");
                        output["data"] = data;
                    }
                    Err(reason) => {
                        output["result"] = json!("degraded");
                        output["fallback_reason"] = json!(reason);
                    }
                }
            }
            if reason.is_some() {
                // Do not publish parsed fields or raw bytes for private or
                // unreviewed material, even when a group label is present.
                output["result"] = json!("degraded");
                output["fallback_reason"] = json!("response_withheld");
            }
            output["raw_evidence"] = evidence(&bytes, content_type, reason);
        }
        Err(reason) => {
            output["result"] = json!("degraded");
            output["fallback_reason"] = json!(reason);
            output["raw_evidence"] =
                evidence(&bytes, content_type, privacy_reason(&bytes, None, None));
        }
    }
    Ok(output)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureCharset {
    Utf8,
    Gbk,
}

fn mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Parse complete parameters, not semicolon fragments inside quoted values.
/// Only HTML semantics are admitted; decoding cannot authorize XML parsing.
fn fixture_charset(content_type: Option<&str>) -> Result<FixtureCharset, &'static str> {
    // No header is the documented legacy HTML-fixture mode.
    let Some(content_type) = content_type else {
        return Ok(FixtureCharset::Gbk);
    };
    let supplied_parameters = content_type.split_once(';');
    let (essence, parameters) = supplied_parameters.unwrap_or((content_type, ""));
    if !essence.trim().eq_ignore_ascii_case("text/html") {
        return Err("unsupported_declared_media_type");
    }
    let mut charset = None;
    let mut parameters = parameters;
    let mut parameter_required = supplied_parameters.is_some();
    loop {
        let trimmed = parameters.trim_start();
        if trimmed.is_empty() {
            if parameter_required {
                return Err("invalid_content_type");
            }
            break;
        }
        let Some(equal) = trimmed.find('=') else {
            return Err("invalid_content_type");
        };
        let name = trimmed[..equal].trim();
        if !mime_token(name) {
            return Err("invalid_content_type");
        }
        let rest = &trimmed[equal + 1..];
        let (value, tail) = if let Some(quoted) = rest.strip_prefix('"') {
            let mut escaped = false;
            let mut closing = None;
            for (index, byte) in quoted.bytes().enumerate() {
                if byte < 0x20 || byte == 0x7f {
                    return Err("invalid_content_type");
                }
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    closing = Some(index);
                    break;
                }
            }
            let Some(end) = closing else {
                return Err("invalid_content_type");
            };
            (&quoted[..end], &quoted[end + 1..])
        } else {
            let end = rest.find(';').unwrap_or(rest.len());
            let value = rest[..end].trim();
            if !mime_token(value) {
                return Err("invalid_content_type");
            }
            (value, &rest[end..])
        };
        if name.eq_ignore_ascii_case("charset") {
            // The quote scanner already established the closing quote. Decode
            // quoted-pairs only after locating parameter boundaries.
            let value = if value.contains('\\') {
                let mut decoded = String::with_capacity(value.len());
                let mut chars = value.chars();
                while let Some(character) = chars.next() {
                    if character == '\\' {
                        decoded.push(chars.next().ok_or("invalid_content_type")?);
                    } else {
                        decoded.push(character);
                    }
                }
                std::borrow::Cow::Owned(decoded)
            } else {
                std::borrow::Cow::Borrowed(value)
            };
            let selected =
                if value.eq_ignore_ascii_case("utf-8") || value.eq_ignore_ascii_case("utf8") {
                    FixtureCharset::Utf8
                } else if ["gb2312", "gbk", "cp936", "euc-cn"]
                    .iter()
                    .any(|label| value.eq_ignore_ascii_case(label))
                {
                    FixtureCharset::Gbk
                } else {
                    return Err("unsupported_declared_charset");
                };
            if charset.is_some_and(|previous| previous != selected) {
                return Err("conflicting_declared_charset");
            }
            charset = Some(selected);
        }
        // Only a complete parameter list continues; a trailing fragment is invalid.
        let tail = tail.trim_start();
        let Some(rest) = tail.strip_prefix(';') else {
            if tail.is_empty() {
                break;
            }
            return Err("invalid_content_type");
        };
        parameters = rest;
        parameter_required = true;
    }
    Ok(charset.unwrap_or(FixtureCharset::Gbk))
}

/// Strict HTML admission precedes decoding. Missing charset retains the
/// legacy GBK mode; unsupported MIME semantics and malformed parameters fail
/// closed and are never reinterpreted as an HTML safety clearance.
fn decode_html(bytes: &[u8], content_type: Option<&str>) -> Result<String, &'static str> {
    match fixture_charset(content_type)? {
        FixtureCharset::Utf8 => decode_utf8(bytes),
        FixtureCharset::Gbk => decode_gbk(bytes),
    }
}

fn decode_utf8(bytes: &[u8]) -> Result<String, &'static str> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| "invalid_utf8")
}

/// glibc iconv is used instead of an undeclared Cargo dependency. GBK is the
/// standard web decoder for the GB2312 label. Conversion is strict: malformed
/// or unsupported input is returned as raw evidence, never silently replaced.
fn decode_gbk(bytes: &[u8]) -> Result<String, &'static str> {
    // SAFETY: both names are static NUL-terminated strings. The returned
    // descriptor is checked before use and owned by Converter.
    let cd = unsafe { iconv_open(c"UTF-8".as_ptr(), c"GBK".as_ptr()) };
    if cd as isize == -1 {
        return Err("gbk_converter_unavailable");
    }
    let _converter = Converter(cd);
    let capacity = bytes
        .len()
        .checked_mul(4)
        .and_then(|n| n.checked_add(8))
        .ok_or("body_too_large")?;
    let mut output = vec![0u8; capacity];
    let mut source = bytes.as_ptr() as *mut libc::c_char;
    let mut source_left = bytes.len();
    let mut target = output.as_mut_ptr().cast::<libc::c_char>();
    let mut target_left = output.len();
    // SAFETY: source and target refer to separate live buffers with the
    // supplied lengths. iconv advances the pointers but does not own them.
    let result = unsafe {
        iconv(
            cd,
            &mut source,
            &mut source_left,
            &mut target,
            &mut target_left,
        )
    };
    if result == usize::MAX || source_left != 0 {
        return Err("invalid_gb2312_or_gbk");
    }
    output.truncate(capacity - target_left);
    String::from_utf8(output).map_err(|_| "invalid_converter_output")
}

unsafe extern "C" {
    fn iconv_open(to: *const libc::c_char, from: *const libc::c_char) -> *mut libc::c_void;
    fn iconv(
        cd: *mut libc::c_void,
        input: *mut *mut libc::c_char,
        input_left: *mut libc::size_t,
        output: *mut *mut libc::c_char,
        output_left: *mut libc::size_t,
    ) -> libc::size_t;
    fn iconv_close(cd: *mut libc::c_void) -> libc::c_int;
}
struct Converter(*mut libc::c_void);
impl Drop for Converter {
    fn drop(&mut self) {
        // SAFETY: this guard closes its uniquely owned descriptor once.
        unsafe {
            iconv_close(self.0);
        }
    }
}

/// Offline-only entry point. `online` never enables transport. The caller
/// owns the input buffer and keeps it out of logs.
pub fn run(input: &str, _online: bool) -> Result<Value, Error> {
    if input.len() > MAX_INPUT {
        return Err(invalid());
    }
    let request: Request = serde_json::from_str(input).map_err(|_| invalid())?;
    match request.operation.as_str() {
        "physics-select" => match request.action.as_str() {
            "capability" => {
                request.allow_only(&[])?;
                Ok(capability())
            }
            "preview" => {
                request.allow_only(&["selection"])?;
                let selection = request.selection.ok_or_else(invalid)?;
                selection.validate()?;
                Ok(json!({
                    "schema_version": 1,
                    "type": "physics_experiment",
                    "result": "preview",
                    "preview": selection.preview(),
                    "network_request_performed": false,
                }))
            }
            "replay" => {
                request.allow_only(&["kind", "data", "content_type"])?;
                let kind = request.kind.ok_or_else(invalid)?;
                let data = request.data.ok_or_else(invalid)?;
                replay(kind, &data, request.content_type.as_deref())
            }
            "options" | "submit" | "captcha" | "resume" | "login" | "verify_session"
            | "logout_preview" | "logout" | "withdraw" => {
                request.allow_only(&[])?;
                Ok(unsupported())
            }
            _ => Err(invalid()),
        },
        "physics-reference" => match request.action.as_str() {
            "catalog" | "retrieve" => {
                request.allow_only(&[])?;
                Ok(reference_blocker())
            }
            _ => Err(invalid()),
        },
        _ => Err(invalid()),
    }
}

pub fn schema() -> Value {
    let selection = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["type", "eid_prefix", "week", "experiment", "weekday", "period"],
        "properties": {
            "type": {"enum": [0, 1]},
            "eid_prefix": {"type": "string", "pattern": "^[A-Za-z]{1,32}$"},
            "week": {"type": "string", "pattern": "^[0-9]{2}$"},
            "experiment": {"type": "string", "pattern": "^[0-9]{4}$"},
            "weekday": {"type": "string", "pattern": "^[0-9]$"},
            "period": {"enum": ["1", "2", "3"]},
        },
    });
    let branch = |operation: &str, action: Value, required: Value, extra: Value| {
        let mut properties = json!({"operation": {"const": operation}, "action": action});
        if let Some(extra) = extra.as_object() {
            for (key, value) in extra {
                properties[key] = value.clone();
            }
        }
        json!({"type": "object", "additionalProperties": false, "required": required, "properties": properties})
    };
    json!({
        "schema_version": 1,
        "description": "Offline-only selection preview and operator-fixture replay. Every request and every selection is a JSON object; positional sequences are refused. No online acceptance, authentication or credential field exists. Privacy scans include inactive text and controls, and a consumed character reference's own output cannot split a private marker; provenance ambiguity or bound overflow stays unreviewed instead of authorizing disclosure. Fallback markup that is never parsed as controls stays unreviewed. Private or unreviewed fixtures withhold originals and parsed fields. Supplied MIME must be text/html with valid quote-aware parameters; XHTML and unknown types remain unreviewed. An absent charset or Content-Type selects the legacy GBK HTML-fixture convention; supported explicit UTF-8/GBK labels are honoured, while conflicting or malformed declarations fail closed.",
        "input": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "oneOf": [
                branch("physics-select", json!({"const": "capability"}), json!(["operation", "action"]), json!({})),
                branch("physics-select", json!({"const": "preview"}), json!(["operation", "action", "selection"]), json!({"selection": selection})),
                branch("physics-select", json!({"const": "replay"}), json!(["operation", "action", "kind", "data"]), json!({
                    "kind": {"enum": ["groups", "verdict"]},
                    "data": {"type": "string", "contentEncoding": "base64", "maxLength": 2796204},
                    "content_type": {"type": ["string", "null"], "description": "Missing and null both mean that no Content-Type was supplied."},
                })),
                branch("physics-select", json!({"enum": ["options", "submit", "captcha", "resume", "login", "verify_session", "logout_preview", "logout", "withdraw"]}), json!(["operation", "action"]), json!({})),
                branch("physics-reference", json!({"enum": ["catalog", "retrieve"]}), json!(["operation", "action"]), json!({})),
            ],
        },
        "output": {
            "type": "object",
            "required": ["schema_version", "type", "result", "network_request_performed"],
            "properties": {
                "schema_version": {"const": 1},
                "type": {"type": "string"},
                "result": {"enum": ["capability", "preview", "parsed", "degraded", "unsupported"]},
                "network_request_performed": {"const": false},
                "raw_evidence": {
                    "type": "object",
                    "required": ["source", "encoding", "content_type", "byte_length", "sha256", "raw_withheld"],
                    "properties": {
                        "source": {"const": "operator_supplied_response_bytes"},
                        "encoding": {"const": "base64"},
                        "content_type": {"type": ["string", "null"], "description": "A known media-type essence; parameters are not echoed."},
                        "byte_length": {"type": "integer", "minimum": 0},
                        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "data": {"type": ["string", "null"], "contentEncoding": "base64"},
                        "raw_withheld": {"type": "boolean"},
                        "raw_withheld_reason": {"enum": ["sensitive_response_material", "challenge_detected", "response_safety_unreviewed", null]},
                    },
                },
            },
        },
        "reference_admission": reference_blocker(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replay_request(kind: &str, body: &[u8], content_type: Option<&str>) -> String {
        let mut request = json!({
            "operation": "physics-select",
            "action": "replay",
            "kind": kind,
            "data": STANDARD.encode(body),
        });
        if let Some(content_type) = content_type {
            request["content_type"] = json!(content_type);
        }
        request.to_string()
    }

    #[test]
    fn unsupported_login_never_claims_authentication() {
        let refused = run(
            r#"{"operation":"physics-select","action":"login","username":"fixture","password":"fixture-only"}"#,
            true,
        );
        let error = refused.unwrap_err();
        assert_eq!(error.code, "invalid_input");
        assert!(!error.message.contains("fixture-only"));
        let value = run(r#"{"operation":"physics-select","action":"login"}"#, true).unwrap();
        assert_eq!(value["result"], "unsupported");
        assert_eq!(value["requests_sent"], 0);
        assert_eq!(value["network_request_performed"], false);
    }

    #[test]
    fn reference_identity_does_not_grant_pdf_rights() {
        for action in ["catalog", "retrieve"] {
            let request =
                json!({"operation": "physics-reference", "action": action, "selection": null});
            assert!(run(&request.to_string(), false).is_err());
            let request = json!({"operation": "physics-reference", "action": action, "password": "fixture-only"});
            assert!(run(&request.to_string(), false).is_err());
        }
        let value = run(
            r#"{"operation":"physics-reference","action":"catalog"}"#,
            false,
        )
        .unwrap();
        assert_eq!(value["result"], "unsupported");
        assert_eq!(value["inventory_verified"], false);
        assert_eq!(value["rights_review_required"], true);
        assert_eq!(value["assessment_review_required"], true);
    }

    #[test]
    fn replay_is_fixture_evidence_not_enrollment() {
        let request = replay_request(
            "verdict",
            "恭喜你，选课成功！".as_bytes(),
            Some("text/html; charset=utf-8"),
        );
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["verdict"], "success_marker");
        assert_eq!(value["online_acceptance"], false);
        assert_eq!(value["enrollment_verified"], false);
        let document = Html::parse_document("<script>恭喜你，选课成功！</script>");
        assert!(classify_verdict(&rendered_text(&document)).is_none());
    }

    #[test]
    fn credential_bearing_fixture_is_withheld() {
        let body = "<form action='/login.php'><input name='txtPwd' value='fixture-secret'>\
                    <input type='hidden' name='csrf_token' value='fixture-token'></form>";
        let request = replay_request("verdict", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("fixture-secret"));
        assert!(!value.to_string().contains("fixture-token"));
    }

    #[test]
    fn credential_material_cannot_escape_via_parsed_groups() {
        let body = "<p>分组代号：opaque-fixture-value 剩余空位：1</p>\
                    <input type='password' value='private-fixture'>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "response_withheld");
        assert!(value["data"].is_null());
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
        assert!(!value.to_string().contains("private-fixture"));
    }

    #[test]
    fn challenge_bearing_fixture_is_withheld() {
        let body = "<form action='/login'><input name='captcha' value='fixture-image'></form>";
        let request = replay_request("verdict", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "challenge_detected"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("fixture-image"));
    }

    #[test]
    fn challenge_material_cannot_escape_via_parsed_groups() {
        let body = "<p>分组代号：opaque-fixture-value 剩余空位：1</p><input name='captcha'>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert!(value["data"].is_null());
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "challenge_detected"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn inactive_challenge_controls_withhold_original_and_parsed_fields() {
        for control in [
            "<input type='hidden' name='captcha' value='opaque-fixture-value'>",
            "<input disabled name='captcha' value='opaque-fixture-value'>",
            "<input style='display:none' name='captcha' value='opaque-fixture-value'>",
            "<template><input name='captcha' value='opaque-fixture-value'></template>",
            "<noscript><input name='captcha' value='opaque-fixture-value'></noscript>",
            "<fieldset disabled><input name='captcha' value='opaque-fixture-value'></fieldset>",
        ] {
            let body = format!("<p>分组代号：opaque-fixture-value 剩余空位：1</p>{control}");
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(value["fallback_reason"], "response_withheld");
            assert!(value["data"].is_null());
            assert_eq!(value["raw_evidence"]["raw_withheld"], true);
            assert!(value["raw_evidence"]["data"].is_null());
            assert!(!value.to_string().contains("opaque-fixture-value"));
            assert!(
                !value
                    .to_string()
                    .contains(&STANDARD.encode(body.as_bytes()))
            );
        }
    }

    #[test]
    fn decoded_inactive_control_names_are_private() {
        // The named HTML entity hides the contiguous marker from source scans;
        // the parsed control name is "verification_code".
        let body = "<p>分组代号：opaque-fixture-value 剩余空位：1</p>\
                    <input type='hidden' name='verification&lowbar;code' value='opaque-fixture-value'>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "response_withheld");
        assert!(value["data"].is_null());
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn inline_split_credential_and_challenge_labels_are_private() {
        for label in [
            "密<b>码</b>",
            "验<b>证</b>码",
            "pass<b>word</b>",
            "cap<b>tcha</b>",
        ] {
            let body = format!(
                "<p>分组代号：opaque-fixture-value 剩余空位：1</p><p>{label}：opaque-fixture-value</p>"
            );
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(value["fallback_reason"], "response_withheld");
            assert!(value["data"].is_null());
            assert_eq!(
                value["raw_evidence"]["raw_withheld_reason"],
                "sensitive_response_material"
            );
            assert!(value["raw_evidence"]["data"].is_null());
            assert!(!value.to_string().contains("opaque-fixture-value"));
            assert!(
                !value
                    .to_string()
                    .contains(&STANDARD.encode(body.as_bytes()))
            );
        }
    }

    #[test]
    fn innocuous_inactive_control_keeps_known_groups_and_original() {
        let body = "<p>分组代号：A 剩余空位：1<b>2</b></p>\
                    <input type='hidden' name='note' value='ordinary'>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["groups"][0]["group_code"], "A");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 12);
        assert_eq!(value["raw_evidence"]["raw_withheld"], false);
        assert_eq!(
            value["raw_evidence"]["data"],
            STANDARD.encode(body.as_bytes())
        );
    }

    #[test]
    fn decoded_chinese_credential_label_is_withheld() {
        let body = "<p>密码：opaque-fixture-value</p>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn inactive_split_labels_and_standard_usernames_are_private() {
        for suffix in [
            "<template><label>pass<b>word</b>:opaque-fixture-value</label></template>",
            "<template><label>密<b>码</b>:opaque-fixture-value</label></template>",
            "<input name='username' autocomplete='username' value='opaque-fixture-value'>",
            "<input name='account' autocomplete='username' value='opaque-fixture-value'>",
        ] {
            let body = format!("<p>分组代号：A 剩余空位：1</p>{suffix}");
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert!(value["data"].is_null());
            assert!(value["raw_evidence"]["data"].is_null());
            assert_eq!(value["raw_evidence"]["raw_withheld"], true);
            assert!(!value.to_string().contains("opaque-fixture-value"));
        }
    }

    #[test]
    fn inactive_one_time_code_control_is_withheld() {
        let body = "<p>分组代号：A 剩余空位：1</p>\
                    <template><input autocomplete=\"one-time-code\" value=\"654321\"></template>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert!(value["data"].is_null());
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("654321"));
    }

    #[test]
    fn privacy_scan_does_not_reuse_business_text_boundaries() {
        // The business projection separates these runs, so the credential only
        // appears in the privacy projection that joins text without a break.
        let body = "<p>分组代号：A 剩余空位：1</p><label>pass<div style=\"display:inline\">word</div>:opaque-fixture-value</label>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert!(value["data"].is_null());
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn entity_encoded_control_name_is_withheld() {
        // The decoded control name is "username"; the source never spells it.
        let body = "<p>分组代号：A 剩余空位：1</p><input name=\"user&amp;name\" value=\"opaque-fixture-value\">";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert!(value["data"].is_null());
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn invalid_reference_like_text_does_not_synthesize_private_markers() {
        for suffix in [
            "pass&amp;2;word",
            "pass&bogus;word",
            "pass&#xZ;word",
            "pass&#;word",
        ] {
            let body = format!("<p>分组代号：A 剩余空位：1</p><p>{suffix}</p>");
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "parsed", "{suffix}");
            assert_eq!(value["data"]["groups"][0]["remaining_seats"], 1);
            assert_eq!(value["raw_evidence"]["raw_withheld"], false);
            assert_eq!(
                value["raw_evidence"]["data"],
                STANDARD.encode(body.as_bytes())
            );
        }
        for reference in ["&amp;", "&lowbar;", "&#38;", "&#x26;"] {
            assert_eq!(without_character_references(reference.as_bytes()), b"");
        }
    }

    #[test]
    fn long_numeric_reference_cannot_hide_private_material() {
        let body = format!(
            "<p>分组代号：A 剩余空位：1</p><p>pass&#{}8203;word:opaque-fixture-value</p>",
            "0".repeat(64)
        );
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(value["data"].is_null());
    }

    fn assert_private_replay(body: &str) {
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "response_withheld");
        assert_eq!(value["network_request_performed"], false);
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert_eq!(value["raw_evidence"]["byte_length"], body.len());
        assert_eq!(
            value["raw_evidence"]["sha256"],
            format!("{:x}", Sha256::digest(body.as_bytes()))
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(value["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
        assert!(
            !value
                .to_string()
                .contains(&STANDARD.encode(body.as_bytes()))
        );
    }

    fn assert_public_replay(body: &str) {
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed", "{body}");
        assert_eq!(value["data"]["groups"][0]["group_code"], "A");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 1);
        assert_eq!(value["network_request_performed"], false);
        assert_eq!(value["raw_evidence"]["raw_withheld"], false);
        assert_eq!(value["raw_evidence"]["byte_length"], body.len());
        assert_eq!(
            value["raw_evidence"]["sha256"],
            format!("{:x}", Sha256::digest(body.as_bytes()))
        );
        assert_eq!(
            value["raw_evidence"]["data"],
            STANDARD.encode(body.as_bytes())
        );
    }

    #[test]
    fn consumed_references_cannot_split_private_markers() {
        for text in [
            "pass&#8203word",
            "pass&shyword",
            "pass&#97word",
            "pass&ampword",
            "pass&#x200Bword",
            "pass&shy;word",
            "pass&semi;word",
            // One reference contributes the first 's', while another must be
            // omitted. Removing all references or only using decoded text
            // misses this combination.
            "pa&#115;s&#97word",
            "pass&#97&#98word",
        ] {
            let body = format!("<p>分组代号：opaque-fixture-value 剩余空位：1</p><p>{text}</p>");
            assert_private_replay(&body);
        }
        let long = format!("pass&#{}97word", "0".repeat(65_536));
        let body = format!("<p>分组代号：opaque-fixture-value 剩余空位：1</p><p>{long}</p>");
        assert_private_replay(&body);
    }

    #[test]
    fn projected_reference_stream_checks_decoded_and_reference_skipping() {
        // The real parse decodes both references. One projected alternative
        // keeps "pass"; the other strips both of them, which is not a hit.
        let marker = 'A';
        let mut matcher = PrivacyMatcher::new();
        matcher
            .feed(
                &format!("{marker}pa{marker}{marker}s{marker}{marker}s{marker}word"),
                marker,
            )
            .unwrap();
        assert!(matcher.hit);
        // Stripping a run of references can also spell a private marker.
        let mut matcher = PrivacyMatcher::new();
        matcher
            .feed(
                &format!("{marker}pa{marker}ordinary{marker}{marker}ss{marker}word"),
                marker,
            )
            .unwrap();
        assert!(matcher.hit);
        // Only the whole decoded output of a consumed reference may be
        // skipped; a partial suffix of a nonreference ampersand is literal.
        let mut matcher = PrivacyMatcher::new();
        matcher
            .feed(&format!("{marker}pass{marker}word"), marker)
            .unwrap_err();
        assert!(!matcher.hit);
        // A reference producing a private-use scalar is ordinary literal
        // text, not a boundary, and cannot split "password" into pieces.
        let mut matcher = PrivacyMatcher::new();
        matcher.feed("pa\u{e000}ssword", marker).unwrap();
        assert!(!matcher.hit);
    }

    #[test]
    fn native_context_and_single_decoding_preserve_safe_controls() {
        for suffix in [
            "<p>pass&amp;shyword</p>",
            "<p>pass&amp;shy;word</p>",
            "<input name='pass&shyword' value='ordinary'>",
            "<input name='note' value='pass&amp=word'>",
            "<script>pass&shyword</script>",
            "<script>pass&shy;word</script>",
            "<p>pass&bogus;word pass&#xZ;word pass&#;word</p>",
            // U+E000 is absent as literal source but is present after HTML
            // decoding; provenance markers must not collide with it.
            "<p>&#57344; ordinary \u{e001}</p>",
        ] {
            let body = format!("<p>分组代号：A 剩余空位：1</p>{suffix}");
            assert_public_replay(&body);
        }
    }

    #[test]
    fn references_in_real_attributes_rcdata_and_templates_are_private() {
        for suffix in [
            "<input name='pass&#97word' value='opaque-fixture-value'>",
            "<input name='pass&shy;word' value='opaque-fixture-value'>",
            "<input pa='&#115;s&#97word' value='opaque-fixture-value'>",
            "<textarea>pass&#97word:opaque-fixture-value</textarea>",
            "<template><label>pass<b>&#97word</b>:opaque-fixture-value</label></template>",
            "<p>pass<b>&ampword</b>:opaque-fixture-value</p>",
            "<p>pass&#97word:opaque-fixture-value</p><noscript>fallback</noscript>",
        ] {
            let body = format!("<p>分组代号：opaque-fixture-value 剩余空位：1</p>{suffix}");
            assert_private_replay(&body);
        }
    }

    #[test]
    fn lost_or_excessive_provenance_never_discloses_originals() {
        let duplicate =
            "<p>分组代号：A 剩余空位：1</p><input name='ordinary' name='&shy;'>".to_owned();
        let malformed = "<p>分组代号：A 剩余空位：1</p><input name='&bogus".to_owned();
        let excessive = format!(
            "<p>分组代号：A 剩余空位：1</p><p>{}</p>",
            "&bogus;".repeat(MAX_PROVENANCE_REFERENCES + 1)
        );
        for body in [duplicate, malformed, excessive] {
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(value["fallback_reason"], "response_withheld");
            assert_eq!(value["raw_evidence"]["raw_withheld"], true);
            assert_eq!(
                value["raw_evidence"]["raw_withheld_reason"],
                "response_safety_unreviewed"
            );
            assert_eq!(value["raw_evidence"]["byte_length"], body.len());
            assert_eq!(
                value["raw_evidence"]["sha256"],
                format!("{:x}", Sha256::digest(body.as_bytes()))
            );
            assert!(value["data"].is_null());
            assert!(value["raw_evidence"]["data"].is_null());
            assert!(
                !value
                    .to_string()
                    .contains(&STANDARD.encode(body.as_bytes()))
            );
        }
    }

    #[test]
    fn quoted_pair_charset_is_decoded_before_selection() {
        let body = "<p>分组代号：A 剩余空位：1</p>";
        let request = replay_request(
            "groups",
            body.as_bytes(),
            Some(r#"text/html; charset="ut\f-8""#),
        );
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 1);
        assert_eq!(value["raw_evidence"]["data"], STANDARD.encode(body));
    }

    #[test]
    fn unrelated_noscript_does_not_weaken_confirmed_privacy_reasons() {
        for (control, reason) in [
            (
                "<input type=\"password\" value=\"x\">",
                "sensitive_response_material",
            ),
            ("<input name=\"captcha\" value=\"x\">", "challenge_detected"),
        ] {
            for body in [
                format!("{control}<noscript>fallback</noscript>"),
                format!("<noscript>fallback</noscript>{control}"),
            ] {
                let request =
                    replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
                let value = run(&request, false).unwrap();
                assert_eq!(value["result"], "degraded");
                assert_eq!(value["raw_evidence"]["raw_withheld_reason"], reason);
                assert_eq!(value["raw_evidence"]["raw_withheld"], true);
                assert!(value["data"].is_null());
                assert!(value["raw_evidence"]["data"].is_null());
            }
        }
    }

    #[test]
    fn noscript_fallback_markup_is_not_reviewed() {
        let body = "<p>分组代号：A 剩余空位：1</p>\
                    <noscript><input name=\"user&lowbar;name\" value=\"opaque-fixture-value\"></noscript>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert!(value["data"].is_null());
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "response_safety_unreviewed"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn replaced_widgets_are_numeric_boundaries() {
        for widget in [
            "<progress max=\"1\" value=\"0\"></progress>",
            "<meter min=\"0\" max=\"1\" value=\"0\"></meter>",
            "<progress max=\"1\" value=\"0\">loading</progress>",
            "<meter min=\"0\" max=\"1\" value=\"0\">loading</meter>",
            "<progress max=\"1\" value=\"0\"><b>loading</b></progress>",
            "<img src=\"fixture.png\" alt=\"\">",
        ] {
            let body = format!("<p>分组代号：A 剩余空位：1{widget}2</p>");
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(value["fallback_reason"], "ambiguous_remaining_seats");
            assert!(value["data"].is_null());
        }
    }

    #[test]
    fn unsupported_document_semantics_remain_unreviewed() {
        let body = br#"<!DOCTYPE html [<!ENTITY a "pass"><!ENTITY b "word">]><html xmlns="http://www.w3.org/1999/xhtml"><body><input name="&a;&b;" value="opaque-fixture-value"/></body></html>"#;
        for mime in [
            "application/xhtml+xml; charset=utf-8",
            "application/xml; charset=utf-8",
            "unknown/type; charset=utf-8",
        ] {
            let request = replay_request("groups", body, Some(mime));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(value["fallback_reason"], "unsupported_declared_media_type");
            assert_eq!(
                value["raw_evidence"]["raw_withheld_reason"],
                "response_safety_unreviewed"
            );
            assert!(value["data"].is_null());
            assert!(value["raw_evidence"]["data"].is_null());
            assert!(!value.to_string().contains("opaque-fixture-value"));
        }
    }

    #[test]
    fn quoted_parameter_cannot_override_real_charset() {
        let mime = "text/html; note=\"x; charset=gbk\"; charset=utf-8";
        let body = "<p>密码:opaque-fixture-value</p>";
        let request = replay_request("groups", body.as_bytes(), Some(mime));
        let value = run(&request, false).unwrap();
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));

        let safe = "<p>分组代号：A 剩余空位：1<b>2</b></p>";
        let request = replay_request("groups", safe.as_bytes(), Some(mime));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 12);
        assert_eq!(
            value["raw_evidence"]["data"],
            STANDARD.encode(safe.as_bytes())
        );
    }

    #[test]
    fn invalid_or_conflicting_mime_parameters_withhold_original() {
        for mime in [
            "text/html; charset=utf-8; charset=gbk",
            "text/html; charset=\"utf-8",
            "text/html; charset=utf-8\"",
            "text/html; note=\"x\"junk; charset=utf-8",
            "text/html; charset",
            "text/html; charset=",
            "text/html; charset=utf-8;",
            "text/html; charset=utf-8;   ",
            "text/html; note=\"ordinary\";",
            "text/html;",
            "text/html;   ",
        ] {
            let request = replay_request("groups", b"ordinary", Some(mime));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(
                value["raw_evidence"]["raw_withheld_reason"],
                "response_safety_unreviewed"
            );
            assert_eq!(value["raw_evidence"]["raw_withheld"], true);
            assert!(value["data"].is_null());
            assert!(value["raw_evidence"]["data"].is_null());
        }
    }

    #[test]
    fn gbk_credential_label_is_withheld_after_decoding() {
        let mut body = b"<p>".to_vec();
        body.extend(from_hex("c3dcc2eb")); // 密码 in GBK.
        body.extend_from_slice(b": opaque-fixture-value</p>");
        let request = replay_request("groups", &body, Some("text/html; charset=gbk"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn escaped_json_credential_key_is_withheld() {
        let body = br#"{"\u0070assword":"opaque-fixture-value"}"#;
        // Exercise the structural probe independently of the raw escape guard.
        assert!(json_sensitive(body));
        let request = replay_request("groups", body, Some("application/json; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn escaped_html_credential_material_is_withheld() {
        let body = b"<input name='pass&#119;ord' value='opaque-fixture-value'>";
        let request = replay_request("groups", body, Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "sensitive_response_material"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn unparsed_fixture_keeps_its_original_bytes() {
        let request = replay_request("groups", b"unexpected", Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "unrecognized_group_listing");
        assert_eq!(value["raw_evidence"]["raw_withheld"], false);
        assert_eq!(value["raw_evidence"]["data"], STANDARD.encode("unexpected"));
        assert_eq!(value["raw_evidence"]["sha256"], hash(b"unexpected"));
    }

    #[test]
    fn parsed_replay_keeps_its_safe_original_bytes() {
        let body = "<p>分组代号：A01</p><p>剩余空位：5</p>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["groups"][0]["group_code"], "A01");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 5);
        assert_eq!(value["raw_evidence"]["raw_withheld"], false);
        assert_eq!(
            value["raw_evidence"]["data"],
            STANDARD.encode(body.as_bytes())
        );
    }

    #[test]
    fn evidence_does_not_echo_private_content_type_parameters() {
        let request = replay_request(
            "groups",
            b"unexpected",
            Some("text/html; proof=opaque-fixture-value; charset=utf-8"),
        );
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(
            value["raw_evidence"]["data"],
            STANDARD.encode(b"unexpected")
        );
        assert_eq!(value["raw_evidence"]["content_type"], "text/html");
        assert!(!value.to_string().contains("opaque-fixture-value"));
    }

    #[test]
    fn undecodable_fixture_is_withheld_without_its_bytes() {
        let request = replay_request("groups", &[0xff, 0xfe], Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["raw_evidence"]["raw_withheld"], true);
        assert_eq!(
            value["raw_evidence"]["raw_withheld_reason"],
            "response_safety_unreviewed"
        );
        assert!(value["raw_evidence"]["data"].is_null());
        assert_eq!(value["raw_evidence"]["byte_length"], 2);
    }

    #[test]
    fn inline_split_count_stays_one_number() {
        let body = "<p>分组代号：A 剩余空位：1<b>2</b></p>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["groups"][0]["group_code"], "A");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 12);
    }

    #[test]
    fn split_count_across_fields_is_refused() {
        let body = "<p>分组代号：A01</p><p>剩余空位：1</p><p>2</p>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "ambiguous_remaining_seats");
    }

    #[test]
    fn replaced_inline_content_does_not_join_digits() {
        let body = "<p>分组代号：A 剩余空位：1<img src='fixture.png'>2</p>";
        let request = replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "ambiguous_remaining_seats");
    }

    #[test]
    fn numeric_continuation_is_not_truncated() {
        for count in ["1.2", "1,234", "1. 2"] {
            let body = format!("<p>分组代号：A 剩余空位：{count}</p>");
            let request =
                replay_request("groups", body.as_bytes(), Some("text/html; charset=utf-8"));
            let value = run(&request, false).unwrap();
            assert_eq!(value["result"], "degraded");
            assert_eq!(value["fallback_reason"], "ambiguous_remaining_seats");
        }
    }

    #[test]
    fn verdict_preserves_inline_but_not_block_adjacency() {
        let inline = "<p>恭喜你，选课成功<b>！</b></p>";
        let request = replay_request(
            "verdict",
            inline.as_bytes(),
            Some("text/html; charset=utf-8"),
        );
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["verdict"], "success_marker");

        let blocks = "<p>恭喜你，选课成功</p><p>！</p>";
        let request = replay_request(
            "verdict",
            blocks.as_bytes(),
            Some("text/html; charset=utf-8"),
        );
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "degraded");
        assert_eq!(value["fallback_reason"], "unrecognized_selection_response");
    }

    #[test]
    fn legacy_gbk_group_listing_is_parsed() {
        let mut body = b"<p>".to_vec();
        body.extend(from_hex("b7d6d7e9b4fabac5a3ba"));
        body.extend(b"A01</p><p>");
        body.extend(from_hex("caa3d3e0bfd5cebba3ba"));
        body.extend(b"5</p>");
        let request = replay_request("groups", &body, None);
        let value = run(&request, false).unwrap();
        assert_eq!(value["result"], "parsed");
        assert_eq!(value["data"]["groups"][0]["group_code"], "A01");
        assert_eq!(value["data"]["groups"][0]["remaining_seats"], 5);
    }

    fn from_hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn requests_must_be_objects() {
        assert!(run(r#"["physics-select","capability"]"#, false).is_err());
        assert!(run(r#"["physics-select","preview"]"#, false).is_err());
        let request = json!({
            "operation": "physics-select",
            "action": "preview",
            "selection": [0, "exp", "01", "1011", "1", "2"],
        });
        assert!(run(&request.to_string(), false).is_err());
    }
}

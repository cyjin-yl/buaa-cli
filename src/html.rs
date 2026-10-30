//! Shared non-executing HTML admission and active source text.
use ego_tree::NodeId;
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer};
use html5ever::tree_builder::{Tracer, TreeBuilder, TreeSink};
use html5ever::{LocalName, TokenizerResult};
use scraper::{ElementRef, Html, HtmlTreeSink, Node, Selector};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

const HTML_NAMESPACE: &str = "http://www.w3.org/1999/xhtml";
const MAX_CHALLENGE_BYTES: usize = 1024 * 1024;
const MAX_CHALLENGE_DOM_ELEMENTS: usize = 32768;
const MAX_CHALLENGE_DOM_DEPTH: usize = 256;
/// Reserve space for parser-generated html/head/body nodes.
const MAX_CHALLENGE_SOURCE_DEPTH: usize = MAX_CHALLENGE_DOM_DEPTH - 8;
/// Bound tree construction between observations of html5ever's live stacks.
const CHALLENGE_PARSE_CHUNK_BYTES: usize = 256;
/// Possible start and end tags admitted before the document is parsed at all.
const MAX_CHALLENGE_SOURCE_TAGS: usize = 32768;
/// A conservative total bound on formatting start tags, before parsing.
/// html5ever may retain formatting entries despite apparent end tags.
const MAX_CHALLENGE_FORMATTING_STARTS: usize = 1024;
const CHALLENGE_MARKERS: [&str; 9] = [
    "captcha",
    "challenge",
    "turnstile",
    "verificationcode",
    "verification-code",
    "verification_code",
    "verification code",
    "验证码",
    "校验码",
];
const FORMATTING_ELEMENTS: [&str; 14] = [
    "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt",
    "u",
];

pub(crate) fn is_html_element(element: ElementRef<'_>) -> bool {
    element.value().name.ns.as_ref() == HTML_NAMESPACE
}

/// Script/style payloads remain inactive in every namespace; template/noscript
/// inertness applies only to their HTML elements, not foreign local-name matches.
pub(crate) fn is_inert_context(element: ElementRef<'_>) -> bool {
    let name = element.value().name();
    matches!(name, "script" | "style")
        || (is_html_element(element) && matches!(name, "template" | "noscript"))
}

pub(crate) fn inert_element(element: ElementRef<'_>) -> bool {
    element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(is_inert_context)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChallengeAssessment {
    Clear,
    Detected,
    Unreviewed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChallengeMime {
    Html { charset: HtmlCharset },
    Xhtml,
    NonHtml { json: bool },
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HtmlCharset {
    /// No charset parameter was declared.
    Absent,
    /// A charset this assessment decodes byte for byte.
    Utf8,
    /// A declared charset this assessment cannot decode.
    Other,
    /// A malformed or conflicting charset parameter.
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceActivity {
    Active,
    Inert,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CssValue {
    Hide,
    Show,
    Unknown,
}

/// Assess only the supplied original body; no script, browser or network
/// behavior is simulated. `complete` means the caller retained the entire
/// response body rather than a transport prefix.
///
/// A valid explicit non-HTML body is never admitted to the HTML parser, and a
/// strongly HTML-shaped document under the wrong MIME is Unreviewed rather
/// than reinterpreted as active HTML. A declared charset this assessment
/// cannot decode is Unreviewed too: a caller that needs legacy bytes decodes
/// them itself and passes the decoded text with an explicit UTF-8 media type.
///
/// This is only the body signal. The caller must merge response-header
/// challenge evidence, persist the observed status and Retry-After, refuse
/// Unreviewed without inventing a CAPTCHA, and retain the configured governor.
pub(crate) fn assess_challenge_body(
    bytes: &[u8],
    content_type: Option<&str>,
    complete: bool,
) -> ChallengeAssessment {
    let mime = challenge_mime(content_type);
    match mime {
        ChallengeMime::Xhtml => {
            // HTML and XML differ in namespaces, void elements and parser repair.
            return ChallengeAssessment::Unreviewed;
        }
        ChallengeMime::Html { charset } => {
            if charset == HtmlCharset::Other || charset == HtmlCharset::Invalid {
                // Another encoding is declared; these bytes are never treated
                // as UTF-8 HTML, so no challenge can be confirmed or excluded.
                return ChallengeAssessment::Unreviewed;
            }
        }
        ChallengeMime::NonHtml { json } => {
            if !complete {
                return ChallengeAssessment::Unreviewed;
            }
            if json {
                // serde_json's ignored-any syntax scan does not establish UTF-8
                // validity for every string payload.
                if std::str::from_utf8(bytes).is_err() {
                    return ChallengeAssessment::Unreviewed;
                }
                // JSON validation is independent of the HTML DOM byte budget.
                return if serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok() {
                    ChallengeAssessment::Clear
                } else {
                    ChallengeAssessment::Unreviewed
                };
            }
            // Binary originals need neither UTF-8 decoding nor an HTML DOM. Only
            // a document-shaped leading prefix makes the declared MIME suspect.
            return if looks_like_html_document(&bytes[..bytes.len().min(MAX_CHALLENGE_BYTES)]) {
                ChallengeAssessment::Unreviewed
            } else {
                ChallengeAssessment::Clear
            };
        }
        ChallengeMime::Ambiguous => {
            // Without a media type the body is not known to be HTML. A valid
            // JSON document is never parsed as HTML, and it is not Clear
            // either because the media type stays unknown.
            if complete
                && std::str::from_utf8(bytes).is_ok()
                && serde_json::from_slice::<serde::de::IgnoredAny>(bytes).is_ok()
            {
                return ChallengeAssessment::Unreviewed;
            }
            if !complete
                && bytes
                    .iter()
                    .copied()
                    .find(|byte| !byte.is_ascii_whitespace())
                    .is_some_and(|byte| matches!(byte, b'{' | b'[' | b'"'))
            {
                // A partial JSON value can contain markup-looking strings.
                return ChallengeAssessment::Unreviewed;
            }
        }
    }

    let (decoded, valid_utf8) = match std::str::from_utf8(bytes) {
        Ok(text) => (text, true),
        Err(error) => {
            let Ok(prefix) = std::str::from_utf8(&bytes[..error.valid_up_to()]) else {
                return ChallengeAssessment::Unreviewed;
            };
            (prefix, false)
        }
    };
    let (text, within_budget) = bounded_text_prefix(decoded);
    let retained_meta = text.as_bytes().windows(4).any(|part| part.eq_ignore_ascii_case(b"meta"));
    let (text, token_budget_complete) = token_work_prefix(text);
    if matches!(mime, ChallengeMime::Html { charset: HtmlCharset::Absent } | ChallengeMime::Ambiguous)
        && (source_encoding_unreviewed(text)
            || (retained_meta && (!token_budget_complete || !within_budget)))
    {
        // Without transport encoding authority, in-document declarations may
        // change even ASCII-looking markup. Do not guess the effective codec.
        return ChallengeAssessment::Unreviewed;
    }
    let complete_source = complete && valid_utf8 && within_budget && token_budget_complete;
    let (assessment, parse_complete) = assess_html_challenge(text);
    if assessment == ChallengeAssessment::Detected {
        if !(complete_source && parse_complete) {
            // The retained prefix cannot establish the document-wide facts that
            // decide whether a challenge control is visible or even decodable.
            // A stylesheet or a charset declaration beyond the retained bytes
            // turns the same document into an unreviewed one, so a truncated
            // source must not confirm a challenge.
            let facts = document_facts(bytes);
            let declared = matches!(
                mime,
                ChallengeMime::Html { charset: HtmlCharset::Absent } | ChallengeMime::Ambiguous
            ) && facts.foreign_charset;
            if facts.stylesheet || declared {
                return ChallengeAssessment::Unreviewed;
            }
        }
        return ChallengeAssessment::Detected;
    }
    if text.contains('\0') {
        // NUL is valid UTF-8, but it may also indicate UTF-16 bytes that were
        // not identified by the metadata. It cannot establish a clear body.
        return ChallengeAssessment::Unreviewed;
    }
    if !complete_source
        || mime == ChallengeMime::Ambiguous
        || assessment == ChallengeAssessment::Unreviewed
    {
        ChallengeAssessment::Unreviewed
    } else {
        ChallengeAssessment::Clear
    }
}

/// The document-wide facts that a truncated source cannot establish.
struct DocumentFacts {
    /// An author stylesheet exists, so a candidate's visibility is unknown.
    stylesheet: bool,
    /// A charset declaration governs the codec of the whole document.
    foreign_charset: bool,
}

/// Scan the body for the document-wide facts that decide whether a challenge
/// control is visible and decodable. The walk is linear over the body and
/// quote-aware, so a `>` inside a quoted value does not end a tag. A tag that
/// never closes, or an attribute value holding an unresolved character
/// reference, keeps its uncertainty: the fact is reported as present, which
/// can only refuse a confirmed challenge, never manufacture one.
fn document_facts(bytes: &[u8]) -> DocumentFacts {
    let mut facts = DocumentFacts {
        stylesheet: false,
        foreign_charset: false,
    };
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index] != b'<' {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        if bytes.get(index + 1).is_some_and(|byte| {
            !byte.is_ascii_alphabetic() && !matches!(*byte, b'!' | b'/' | b'?')
        }) {
            // The HTML tokenizer reconsumes an invalid tag-open character as
            // text; a subsequent '<' can still start a real tag.
            index += 1;
            continue;
        }
        if bytes[index..].starts_with(b"<!--") {
            match comment_end(&bytes[index + 4..]) {
                CommentEnd::Closed(offset) | CommentEnd::Bang(offset) => {
                    index += 4 + offset;
                    continue;
                }
                CommentEnd::Unterminated => {
                    facts.stylesheet = true;
                    facts.foreign_charset = true;
                    break;
                }
            }
        }
        if bytes[index..].starts_with(b"<![CDATA[") {
            // Without namespace state this may be CDATA or a bogus comment;
            // do not guess which terminator exposes the following source.
            facts.stylesheet = true;
            facts.foreign_charset = true;
            break;
        }
        let after = &bytes[index..];
        let doctype = ascii_at(after, 0, b"<!doctype")
            && html_name_delimiter(after.get(b"<!doctype".len()));
        if doctype {
            let mut quote = None;
            let mut end = None;
            for (offset, byte) in after.iter().copied().enumerate().skip(b"<!doctype".len()) {
                match (quote, byte) {
                    (Some(open), byte) if open == byte => quote = None,
                    (Some(_), b'>') => {
                        // A malformed doctype can instead enter bogus-doctype
                        // state, in which this would terminate the token.
                        facts.stylesheet = true;
                        facts.foreign_charset = true;
                        return facts;
                    }
                    (None, b'\'' | b'"') => quote = Some(byte),
                    (None, b'>') => {
                        end = Some(offset);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(end) = end {
                index += end + 1;
                continue;
            }
            facts.stylesheet = true;
            facts.foreign_charset = true;
            break;
        }
        let bogus_end = after.starts_with(b"</")
            && after.get(2).is_some_and(|byte| !byte.is_ascii_alphabetic() && *byte != b'>');
        if after.starts_with(b"<?") || after.starts_with(b"<!") || bogus_end {
            // Bogus comments end at the first '>', regardless of quotes.
            if let Some(end) = bytes[index + 2..].iter().position(|byte| *byte == b'>') {
                index += end + 3;
                continue;
            }
            facts.stylesheet = true;
            facts.foreign_charset = true;
            break;
        }
        index += 1;
        let name_start = index;
        while index < bytes.len()
            && !is_html_space(bytes[index])
            && bytes[index] != b'>'
            && bytes[index] != b'/'
        {
            index += 1;
        }
        let name = &bytes[name_start..index];
        let mut relation: Option<Option<&[u8]>> = None;
        let mut charset: Option<Option<&[u8]>> = None;
        let mut content_type: Option<Option<&[u8]>> = None;
        let mut closed = false;
        loop {
            while index < bytes.len() && is_html_space(bytes[index]) {
                index += 1;
            }
            if index >= bytes.len() {
                break;
            }
            if bytes[index] == b'>' {
                index += 1;
                closed = true;
                break;
            }
            if bytes[index] == b'/' {
                index += 1;
                continue;
            }
            let attribute_start = index;
            while index < bytes.len()
                && !is_html_space(bytes[index])
                && bytes[index] != b'='
                && bytes[index] != b'>'
                && bytes[index] != b'/'
            {
                index += 1;
            }
            let attribute = &bytes[attribute_start..index];
            let mut cursor = index;
            while cursor < bytes.len() && is_html_space(bytes[cursor]) {
                cursor += 1;
            }
            let mut value: Option<&[u8]> = None;
            if cursor < bytes.len() && bytes[cursor] == b'=' {
                cursor += 1;
                while cursor < bytes.len() && is_html_space(bytes[cursor]) {
                    cursor += 1;
                }
                if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'') {
                    let quote = bytes[cursor];
                    cursor += 1;
                    let value_start = cursor;
                    while cursor < bytes.len() && bytes[cursor] != quote {
                        cursor += 1;
                    }
                    value = Some(&bytes[value_start..cursor]);
                    if cursor < bytes.len() {
                        cursor += 1;
                    }
                } else {
                    let value_start = cursor;
                    while cursor < bytes.len()
                        && !is_html_space(bytes[cursor])
                        && bytes[cursor] != b'>'
                    {
                        cursor += 1;
                    }
                    value = Some(&bytes[value_start..cursor]);
                }
                index = cursor;
            }
            if attribute.eq_ignore_ascii_case(b"rel") {
                relation.get_or_insert(value);
            } else if attribute.eq_ignore_ascii_case(b"charset") {
                charset.get_or_insert(value);
            } else if attribute.eq_ignore_ascii_case(b"http-equiv") {
                content_type.get_or_insert(value);
            }
        }
        if !closed {
            // An unfinished token can consume or obscure later document facts.
            facts.stylesheet = true;
            facts.foreign_charset = true;
            break;
        }
        if name.eq_ignore_ascii_case(b"style") {
            facts.stylesheet = true;
        } else if name.eq_ignore_ascii_case(b"link") {
            if let Some(value) = relation.flatten() {
                // An unresolved character reference can spell any relation
                // token, so it keeps the stylesheet possibility open.
                if value.contains(&b'&')
                    || value
                        .split(|byte: &u8| is_html_space(*byte))
                        .any(|token| token.eq_ignore_ascii_case(b"stylesheet"))
                {
                    facts.stylesheet = true;
                }
            }
        } else if name.eq_ignore_ascii_case(b"meta") {
            if let Some(value) = charset.map(|value| value.unwrap_or_default()) {
                // A declared UTF-8 keeps the retained prefix authoritative; any
                // other declared charset governs the whole document.
                if value.contains(&b'&')
                    || (!value.eq_ignore_ascii_case(b"utf-8")
                        && !value.eq_ignore_ascii_case(b"utf8"))
                {
                    facts.foreign_charset = true;
                }
            }
            if let Some(value) = content_type.flatten() {
                // `content-type` overrides the effective codec of the whole
                // document; other http-equiv values do not.
                if value.contains(&b'&') || value.eq_ignore_ascii_case(b"content-type") {
                    facts.foreign_charset = true;
                }
            }
        }
    }
    facts
}

/// The HTML whitespace set.
fn is_html_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

fn bounded_text_prefix(text: &str) -> (&str, bool) {
    if text.len() <= MAX_CHALLENGE_BYTES {
        return (text, true);
    }
    let mut end = MAX_CHALLENGE_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], false)
}

/// Bound unfinished-token attribute work before either html5ever tokenizer
/// sees it. A conservative '<' to '>' span cap also covers malformed quotes;
/// false positives refuse rather than attempting tokenizer error recovery.
fn token_work_prefix(text: &str) -> (&str, bool) {
    let mut start = None;
    let mut quote = None;
    // tag-name, before-attribute, attribute-name, after-name,
    // before-value, unquoted-value, after-quoted-value.
    let mut state = 0u8;
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'<' && start.is_none() {
            start = Some(index);
            state = 0;
            continue;
        }
        if let Some(open) = start {
            if index - open > 8192 {
                return (&text[..open], false);
            }
            if let Some(open_quote) = quote {
                if byte == open_quote {
                    quote = None;
                    state = 6;
                }
            } else if byte == b'\'' || byte == b'"' {
                // HTML only starts a quoted attribute value after '='.
                // A quote inside an unquoted value is ordinary data; refuse
                // that unsupported syntax before either tokenizer can amass
                // an unbounded attribute list behind a misidentified '>'.
                if state != 4 {
                    return (&text[..open], false);
                }
                quote = Some(byte);
            } else if byte == b'>' {
                start = None;
            } else {
                let whitespace = matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ');
                state = match state {
                    0 if whitespace => 1,
                    0 => 0,
                    1 if whitespace || byte == b'/' => 1,
                    1 => 2,
                    2 if byte == b'=' => 4,
                    2 if whitespace => 3,
                    2 => 2,
                    3 if byte == b'=' => 4,
                    3 if whitespace => 3,
                    3 => 2,
                    4 if whitespace => 4,
                    4 => 5,
                    5 if whitespace => 1,
                    5 => 5,
                    6 if whitespace || byte == b'/' => 1,
                    _ => return (&text[..open], false),
                };
            }
        }
    }
    (text, true)
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

fn ascii_suffix(value: &str, suffix: &str) -> bool {
    value
        .as_bytes()
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.len() == suffix.len() && tail.eq_ignore_ascii_case(suffix.as_bytes()))
}

fn challenge_mime(content_type: Option<&str>) -> ChallengeMime {
    let Some(content_type) = content_type else {
        return ChallengeMime::Ambiguous;
    };
    let essence = mime_trim(content_type.split(';').next().unwrap_or_default());
    let Some((kind, subtype)) = essence.split_once('/') else {
        return ChallengeMime::Ambiguous;
    };
    if !mime_token(kind) || !mime_token(subtype) || kind.contains('*') || subtype.contains('*') {
        return ChallengeMime::Ambiguous;
    }
    if kind.eq_ignore_ascii_case("text") && subtype.eq_ignore_ascii_case("html") {
        ChallengeMime::Html {
            charset: html_charset(content_type),
        }
    } else if kind.eq_ignore_ascii_case("application") && subtype.eq_ignore_ascii_case("xhtml+xml") {
        ChallengeMime::Xhtml
    } else {
        ChallengeMime::NonHtml {
            json: kind.eq_ignore_ascii_case("application")
                // GitHub's documented raw blob representation is not a JSON
                // envelope despite this exact media subtype's suffix.
                && !subtype.eq_ignore_ascii_case("vnd.github.raw+json")
                && (subtype.eq_ignore_ascii_case("json") || ascii_suffix(subtype, "+json")),
        }
    }
}

fn mime_trim(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// Read the declared charset of a text/html content type. Conflicting or
/// malformed charset parameters are invalid, and only UTF-8 is decoded.
fn html_charset(content_type: &str) -> HtmlCharset {
    match declared_html_charset(content_type) {
        Err(()) => HtmlCharset::Invalid,
        Ok(None) => HtmlCharset::Absent,
        Ok(Some(value)) if value.eq_ignore_ascii_case("utf-8") || value.eq_ignore_ascii_case("utf8") => HtmlCharset::Utf8,
        Ok(Some(_)) => HtmlCharset::Other,
    }
}

/// Parse charset parameters with the same quote, escape and conflict rules as
/// challenge admission. The caller decides which declared encodings it supports.
pub(crate) fn declared_html_charset(content_type: &str) -> Result<Option<std::borrow::Cow<'_, str>>, ()> {
    let mut declared: Option<std::borrow::Cow<'_, str>> = None;
    let Some((_, mut remaining)) = content_type.split_once(';') else {
        return Ok(None);
    };
    loop {
        let Some(end) = mime_parameter_end(remaining) else {
            return Err(());
        };
        let parameter = &remaining[..end];
        let next = remaining.get(end + 1..);
        let parameter = mime_trim(parameter);
        if parameter.is_empty() {
            if let Some(rest) = next {
                remaining = rest;
                continue;
            }
            break;
        }
        let Some((name, value)) = parameter.split_once('=') else {
            return Err(());
        };
        let name = mime_trim(name);
        if !mime_token(name) {
            return Err(());
        }
        if !name.eq_ignore_ascii_case("charset") {
            if let Some(rest) = next {
                remaining = rest;
                continue;
            }
            break;
        }
        let value = mime_trim(value);
        let quoted = value.starts_with('"');
        let value = match value.strip_prefix('"') {
            Some(unquoted) => match unquoted.strip_suffix('"') {
                Some(inner) => inner,
                None => return Err(()),
            },
            None => value,
        };
        let value = if quoted && value.contains('\\') {
            let mut decoded = String::with_capacity(value.len());
            let mut chars = value.chars();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    let Some(escaped) = chars.next() else {
                        return Err(());
                    };
                    decoded.push(escaped);
                } else {
                    decoded.push(ch);
                }
            }
            std::borrow::Cow::Owned(decoded)
        } else {
            std::borrow::Cow::Borrowed(value)
        };
        if value.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
            })
        {
            return Err(());
        }
        if let Some(existing) = declared.as_ref()
            && !existing.eq_ignore_ascii_case(&value)
        {
            return Err(());
        }
        declared = Some(value);
        if let Some(rest) = next {
            remaining = rest;
        } else {
            break;
        }
    }
    Ok(declared)
}

/// Find the next unquoted MIME parameter boundary; quoted-pair escapes do
/// not terminate their enclosing value.
fn mime_parameter_end(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut quoted = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' if quoted => {
                if index + 1 >= bytes.len() {
                    return None;
                }
                index += 2;
            }
            b'"' => {
                quoted = !quoted;
                index += 1;
            }
            b';' if !quoted => return Some(index),
            _ => index += 1,
        }
    }
    (!quoted).then_some(bytes.len())
}

fn ascii_at(bytes: &[u8], offset: usize, expected: &[u8]) -> bool {
    bytes
        .get(offset..offset.saturating_add(expected.len()))
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn html_name_delimiter(byte: Option<&u8>) -> bool {
    byte.is_none_or(|byte| matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ' | b'/' | b'>'))
}

enum CommentEnd {
    Closed(usize),
    Bang(usize),
    Unterminated,
}

/// Locate the end of a leading HTML comment. `-->` closes a comment and the
/// `--!>` bang form closes it as well, leaving live document content behind.
fn comment_end(bytes: &[u8]) -> CommentEnd {
    if bytes.starts_with(b">") {
        return CommentEnd::Bang(1);
    }
    if bytes.starts_with(b"->") {
        return CommentEnd::Bang(2);
    }
    let mut index = 0usize;
    while index + 2 < bytes.len() {
        if bytes[index] == b'-' && bytes[index + 1] == b'-' {
            match bytes.get(index + 2) {
                Some(b'>') => return CommentEnd::Closed(index + 3),
                Some(b'!') if bytes.get(index + 3) == Some(&b'>') => return CommentEnd::Bang(index + 4),
                _ => {}
            }
        }
        index += 1;
    }
    CommentEnd::Unterminated
}

/// A bounded leading-shape check for MIME mismatch only. It never produces
/// Detected and never scans arbitrary binary offsets for an incidental tag.
fn looks_like_html_document(mut bytes: &[u8]) -> bool {
    if let Some(after_bom) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        bytes = after_bom;
    }
    loop {
        let whitespace = bytes
            .iter()
            .take_while(|byte| matches!(**byte, b'\t' | b'\n' | 0x0c | b'\r' | b' '))
            .count();
        bytes = &bytes[whitespace..];
        if !bytes.starts_with(b"<!--") {
            break;
        }
        match comment_end(&bytes[4..]) {
            CommentEnd::Closed(offset) => bytes = &bytes[4 + offset..],
            // The remainder is live document content, and an unterminated
            // comment cannot prove that the body is not HTML either.
            CommentEnd::Bang(_) | CommentEnd::Unterminated => return true,
        }
    }
    if bytes.first() == Some(&b'<')
        && ascii_at(bytes, 1, b"html")
        && html_name_delimiter(bytes.get(1 + b"html".len()))
    {
        return true;
    }
    // The HTML tokenizer repairs missing whitespace and malformed names.
    bytes.first() == Some(&b'<') && ascii_at(bytes, 1, b"!doctype")
}

fn challenge_marker_matches(value: &str) -> bool {
    CHALLENGE_MARKERS.iter().any(|marker| {
        value
            .as_bytes()
            .windows(marker.len())
            .any(|part| part.eq_ignore_ascii_case(marker.as_bytes()))
    })
}

fn challenge_text_cue(value: &str) -> bool {
    if challenge_marker_matches(value) {
        return true;
    }
    // Only the spaced English marker can emerge from whitespace folding.
    if !value.as_bytes().windows(b"verification".len())
        .any(|part| part.eq_ignore_ascii_case(b"verification"))
    {
        return false;
    }
    let mut normalized = String::new();
    for word in value.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(word);
    }
    challenge_marker_matches(&normalized)
}

fn known_challenge_widget(element: ElementRef<'_>) -> bool {
    element.value().attr("class").is_some_and(|classes| {
        classes
            .split_ascii_whitespace()
            .any(|class| matches!(class, "g-recaptcha" | "h-captcha" | "cf-turnstile"))
    })
}

fn challenge_control(element: ElementRef<'_>) -> bool {
    is_html_element(element)
        && matches!(
            element.value().name(),
            "input" | "select" | "textarea" | "button"
        )
}

fn challenge_candidate(element: ElementRef<'_>) -> bool {
    if !is_html_element(element) {
        return false;
    }
    if known_challenge_widget(element) {
        return true;
    }
    let value = element.value();
    match value.name() {
        "input" | "select" | "textarea" | "button" => ["name", "id", "class", "autocomplete"]
            .into_iter()
            .filter_map(|name| value.attr(name))
            .any(challenge_marker_matches),
        "form" => value.attr("action").is_some_and(challenge_marker_matches),
        "iframe" => value.attr("src").is_some_and(challenge_marker_matches),
        _ => false,
    }
}

fn effectively_disabled(
    control: ElementRef<'_>,
    disabled_fieldsets: &HashMap<NodeId, Option<NodeId>>,
) -> bool {
    if control.value().attr("disabled").is_some() {
        return true;
    }
    // Keep the first-legend exception aligned with recordings/session.rs.
    let mut legend_ancestors = HashSet::new();
    for ancestor in control.ancestors().filter_map(ElementRef::wrap) {
        if ancestor.value().name() == "legend" {
            legend_ancestors.insert(ancestor.id());
        }
        if let Some(first_legend) = disabled_fieldsets.get(&ancestor.id())
            && !first_legend.is_some_and(|legend| legend_ancestors.contains(&legend))
        {
            return true;
        }
    }
    false
}

/// Split only at top-level declaration delimiters. Unsupported or malformed
/// CSS syntax cannot establish a candidate's visibility.
pub(crate) fn split_declarations(style: &str) -> Result<Vec<(&str, &str)>, ()> {
    let bytes = style.as_bytes();
    let mut declarations = Vec::new();
    let mut blocks = Vec::new();
    let mut index = 0usize;
    let mut segment_start = 0usize;
    let mut colon: Option<usize> = None;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => {
                let quote = bytes[index];
                index += 1;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        if index + 1 >= bytes.len() {
                            return Err(());
                        }
                        index += 2;
                        continue;
                    }
                    if matches!(bytes[index], b'\n' | b'\r' | 0x0c) {
                        return Err(());
                    }
                    let closing = bytes[index] == quote;
                    index += 1;
                    if closing {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(());
                }
                continue;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let Some(offset) = style[index + 2..].find("*/") else {
                    return Err(());
                };
                index += 2 + offset + 2;
                continue;
            }
            b'\\' => {
                if index + 1 >= bytes.len() {
                    return Err(());
                }
                index += 2;
            }
            b'(' | b'[' | b'{' => {
                blocks.push(match bytes[index] {
                    b'(' => b')',
                    b'[' => b']',
                    _ => b'}',
                });
                index += 1;
            }
            b')' | b']' | b'}' => {
                if blocks.pop() != Some(bytes[index]) {
                    return Err(());
                }
                index += 1;
            }
            b':' if colon.is_none() && blocks.is_empty() => {
                colon = Some(index);
                index += 1;
            }
            b';' if blocks.is_empty() => {
                push_declaration(style, segment_start, index, colon, &mut declarations);
                segment_start = index + 1;
                colon = None;
                index += 1;
            }
            _ => index += 1,
        }
    }
    if !blocks.is_empty() {
        return Err(());
    }
    push_declaration(style, segment_start, bytes.len(), colon, &mut declarations);
    Ok(declarations)
}

fn push_declaration<'a>(
    style: &'a str,
    start: usize,
    end: usize,
    colon: Option<usize>,
    declarations: &mut Vec<(&'a str, &'a str)>,
) {
    let Some(colon) = colon else {
        return;
    };
    let property = css_trim(&style[start..colon]);
    let value = css_trim(&style[colon + 1..end]);
    if property.is_empty() || value.is_empty() {
        return;
    }
    declarations.push((property, value));
}

fn css_whitespace(ch: char) -> bool {
    matches!(ch, '\t' | '\n' | '\u{000c}' | '\r' | ' ')
}

pub(crate) fn css_trim(value: &str) -> &str {
    value.trim_matches(css_whitespace)
}

/// Remove CSS comments that are not inside a quoted string. An unterminated
/// comment leaves the value unresolved.
pub(crate) fn strip_css_comments(value: &str) -> Option<std::borrow::Cow<'_, str>> {
    if !value.contains("/*") {
        return Some(std::borrow::Cow::Borrowed(value));
    }
    let bytes = value.as_bytes();
    let mut result = String::with_capacity(value.len());
    let mut index = 0usize;
    let mut copied = 0usize;
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(open) => {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == open {
                    quote = None;
                }
                index += 1;
            }
            None => {
                if byte == b'"' || byte == b'\'' {
                    quote = Some(byte);
                    index += 1;
                } else if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    result.push_str(value.get(copied..index)?);
                    let rest = value.get(index + 2..)?;
                    let end = rest.find("*/")?;
                    result.push(' ');
                    index += 2 + end + 2;
                    copied = index;
                } else {
                    index += 1;
                }
            }
        }
    }
    result.push_str(value.get(copied..)?);
    Some(std::borrow::Cow::Owned(result))
}

/// Split a trailing `!important` marker from a declaration value.
pub(crate) fn split_important(value: &str) -> (&str, bool) {
    let trimmed = value.trim_end_matches(css_whitespace);
    let Some(marker_start) = trimmed.len().checked_sub("important".len()) else {
        return (trimmed, false);
    };
    let Some(marker) = trimmed.get(marker_start..) else {
        return (trimmed, false);
    };
    if !marker.eq_ignore_ascii_case("important") {
        return (trimmed, false);
    }
    let Some(head) = trimmed.get(..marker_start) else {
        return (trimmed, false);
    };
    let Some(head) = head.trim_end_matches(css_whitespace).strip_suffix('!') else {
        return (trimmed, false);
    };
    (head.trim_end_matches(css_whitespace), true)
}

/// Classify one declaration. Only plain keywords are understood; functions,
/// strings, comments and inherited values stay unresolved.
fn classify_declaration(property: &str, value: &str) -> Option<(CssValue, bool)> {
    let property = css_trim(property).to_ascii_lowercase();
    if !matches!(
        property.as_str(),
        "display" | "visibility" | "content-visibility"
    ) {
        return None;
    }
    let Some(value) = strip_css_comments(value) else {
        return Some((CssValue::Unknown, false));
    };
    let (body, important) = split_important(css_trim(&value));
    let body = css_trim(body).to_ascii_lowercase();
    if body.contains('(') || body.contains('"') || body.contains('\'') {
        return Some((CssValue::Unknown, important));
    }
    let kind = match property.as_str() {
        "display" => match body.as_str() {
            "none" => CssValue::Hide,
            "inline" | "block" | "inline-block" | "flow-root" | "list-item" | "table" | "flex"
            | "grid" | "run-in" | "inline-table" | "table-row" | "table-cell"
            | "table-caption" | "table-column" | "table-column-group" | "table-row-group"
            | "table-footer-group" | "inline-flex" | "inline-grid" => CssValue::Show,
            _ => CssValue::Unknown,
        },
        "visibility" => match body.as_str() {
            "hidden" | "collapse" => CssValue::Hide,
            "visible" => CssValue::Show,
            _ => CssValue::Unknown,
        },
        _ => match body.as_str() {
            "hidden" => CssValue::Hide,
            "visible" => CssValue::Show,
            // `auto` may skip rendering of off-screen content.
            _ => CssValue::Unknown,
        },
    };
    Some((kind, important))
}

/// One element's own inline style, resolved through the declaration cascade: a
/// later declaration of the same property wins, and `!important` wins over a
/// plain declaration of the same property.
#[derive(Clone, Copy, Default)]
struct StyleKinds {
    display: Option<(CssValue, bool)>,
    visibility: Option<(CssValue, bool)>,
    content_visibility: Option<(CssValue, bool)>,
    syntax_unresolved: bool,
}

impl StyleKinds {
    fn of(style: &str) -> StyleKinds {
        let mut kinds = StyleKinds::default();
        let Ok(declarations) = split_declarations(style) else {
            kinds.syntax_unresolved = true;
            return kinds;
        };
        for (property, value) in declarations {
            if css_trim(property).eq_ignore_ascii_case("all") {
                // `all` resets the properties tracked here and participates in
                // their cascade; do not assume an earlier hide still wins.
                kinds.syntax_unresolved = true;
                continue;
            }
            // CSS escapes or comments in a property name can spell a relevant
            // property without matching its literal source bytes.
            if property.contains('\\') || property.contains("/*") {
                kinds.syntax_unresolved = true;
                continue;
            }
            let Some((kind, important)) = classify_declaration(property, value) else {
                // Other properties can affect visibility or interaction (for
                // example opacity, clipping, positioning, or transforms).
                // A standalone custom property has no effect without a
                // consuming declaration, which is itself classified above.
                if !property.starts_with("--") {
                    kinds.syntax_unresolved = true;
                }
                continue;
            };
            let property = css_trim(property).to_ascii_lowercase();
            let target = match property.as_str() {
                "display" => &mut kinds.display,
                "visibility" => &mut kinds.visibility,
                _ => &mut kinds.content_visibility,
            };
            let replaced = match target {
                Some((_, previous_important)) => important || !*previous_important,
                None => true,
            };
            if replaced {
                *target = Some((kind, important));
            }
        }
        kinds
    }

    /// The element itself is hidden by its own declarations.
    fn hides_itself(&self) -> bool {
        !self.syntax_unresolved
            && (matches!(self.display, Some((CssValue::Hide, _)))
                || matches!(self.visibility, Some((CssValue::Hide, _)))
                || matches!(self.content_visibility, Some((CssValue::Hide, _))))
    }

    /// The element itself is hidden and no author rule can reveal it again.
    fn hides_itself_importantly(&self) -> bool {
        !self.syntax_unresolved
            && (self.display == Some((CssValue::Hide, true))
                || self.visibility == Some((CssValue::Hide, true))
                || self.content_visibility == Some((CssValue::Hide, true)))
    }

    /// Descendants may override an inherited visibility, unlike an ancestor's
    /// display or content-visibility.
    fn hides_descendants_importantly(&self) -> bool {
        !self.syntax_unresolved
            && (self.display == Some((CssValue::Hide, true))
                || self.content_visibility == Some((CssValue::Hide, true)))
    }

    fn unresolved(&self) -> bool {
        self.syntax_unresolved
            || matches!(self.display, Some((CssValue::Unknown, _)))
            || matches!(self.visibility, Some((CssValue::Unknown, _)))
            || matches!(self.content_visibility, Some((CssValue::Unknown, _)))
    }
}

/// An author stylesheet can hide or reveal any candidate, so a candidate in a
/// styled document has no reliably established visibility.
fn author_stylesheet_present(document: &Html) -> bool {
    let Ok(styles) = Selector::parse("style") else {
        return true;
    };
    if document
        .select(&styles)
        .any(|style| !inert_ancestor(style))
    {
        return true;
    }
    let Ok(links) = Selector::parse("link") else {
        return true;
    };
    document.select(&links).any(|link| {
        is_html_element(link)
            && !inert_ancestor(link)
            && link.value().attr("rel").is_some_and(|rel| {
                rel.split_ascii_whitespace()
                    .any(|value| value.eq_ignore_ascii_case("stylesheet"))
            })
    })
}

/// Inertness of the ancestors only; an element is not inert because of itself.
fn inert_ancestor(element: ElementRef<'_>) -> bool {
    element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(is_inert_context)
}

/// The element and its ancestors, nearest ancestor first.
fn element_lineage(element: ElementRef<'_>) -> Vec<ElementRef<'_>> {
    std::iter::once(element)
        .chain(element.ancestors().filter_map(ElementRef::wrap))
        .collect()
}

fn challenge_activity(
    element: ElementRef<'_>,
    disabled_fieldsets: &HashMap<NodeId, Option<NodeId>>,
    stylesheet_present: bool,
) -> SourceActivity {
    let value = element.value();
    if value.name() == "iframe" && value.attr("srcdoc").is_some() {
        // srcdoc overrides fallback src; neither its document nor its
        // effective browser activity has been established here.
        return SourceActivity::Ambiguous;
    }
    // An externally associated control can submit a form even when the form
    // itself is hidden or inert. A static ancestry check cannot exclude it.
    let form_action = value.name() == "form";
    let structurally_hidden = || {
        if form_action {
            SourceActivity::Ambiguous
        } else {
            SourceActivity::Inert
        }
    };
    let visibility_hidden = || {
        if form_action || element.children().any(|child| ElementRef::wrap(child).is_some()) {
            // Descendants may override inherited visibility.
            SourceActivity::Ambiguous
        } else {
            SourceActivity::Inert
        }
    };
    // A hidden input never renders and never takes part in the interaction.
    if value.name() == "input"
        && value
            .attr("type")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("hidden"))
    {
        return SourceActivity::Inert;
    }
    // The disabled state is a DOM fact; no style can re-enable a control.
    if challenge_control(element) && effectively_disabled(element, disabled_fieldsets) {
        return SourceActivity::Inert;
    }
    let lineage = element_lineage(element);
    // Inert contexts never render their contents.
    if lineage.iter().any(|member| is_inert_context(*member)) {
        return SourceActivity::Inert;
    }
    if lineage.iter().any(|member| {
        is_html_element(*member)
            && matches!(member.value().name(), "dialog" | "details")
            && member.value().attr("open").is_none()
    }) {
        return SourceActivity::Ambiguous;
    }
    // The inert attribute is a DOM state, not a style, so no stylesheet can
    // make an inert subtree interactive again.
    if lineage
        .iter()
        .any(|member| member.value().attr("inert").is_some())
    {
        return structurally_hidden();
    }
    // Popovers are not necessarily shown; script/browser state is unavailable.
    if lineage.iter().any(|member| {
        is_html_element(*member) && member.value().attr("popover").is_some()
    }) {
        return SourceActivity::Ambiguous;
    }
    let styles: Vec<StyleKinds> = lineage
        .iter()
        .map(|member| StyleKinds::of(member.value().attr("style").unwrap_or_default()))
        .collect();
    let own = styles[0];
    if stylesheet_present {
        // An author rule can reveal or hide the candidate, and an important
        // inline declaration outranks such a rule.
        if own.hides_descendants_importantly()
            || styles[1..]
                .iter()
                .any(StyleKinds::hides_descendants_importantly)
        {
            return structurally_hidden();
        }
        if own.hides_itself_importantly() {
            // A stylesheet can expose generated descendants even on a leaf
            // whose own inherited visibility is hidden.
            return SourceActivity::Ambiguous;
        }
        return SourceActivity::Ambiguous;
    }
    if own.hides_itself() {
        if matches!(own.display, Some((CssValue::Hide, _)))
            || matches!(own.content_visibility, Some((CssValue::Hide, _)))
        {
            return structurally_hidden();
        }
        return visibility_hidden();
    }
    let mut ambiguous = false;
    let mut visibility = None;
    for (member, style) in lineage.iter().zip(&styles) {
        // The default UA rule for `hidden` can be overridden by this
        // element's own author display declaration. The until-found state
        // needs browser behavior that this static assessment does not model.
        if let Some(hidden) = member.value().attr("hidden") {
            if hidden.eq_ignore_ascii_case("until-found") || style.syntax_unresolved {
                ambiguous = true;
            } else {
                match style.display {
                    None | Some((CssValue::Hide, _)) => return structurally_hidden(),
                    Some((CssValue::Show, _)) => {}
                    Some((CssValue::Unknown, _)) => ambiguous = true,
                }
            }
        }
        // An ancestor's display/content-visibility cannot be overridden by a
        // descendant. Visibility, in contrast, inherits and the nearest
        // explicitly specified value wins even across !important boundaries.
        if !style.syntax_unresolved
            && (matches!(style.display, Some((CssValue::Hide, _)))
                || matches!(style.content_visibility, Some((CssValue::Hide, _))))
        {
            return structurally_hidden();
        }
        if visibility.is_none() {
            visibility = if style.syntax_unresolved {
                Some(CssValue::Unknown)
            } else {
                style.visibility.map(|(value, _)| value)
            };
        }
        if style.unresolved() {
            ambiguous = true;
        }
    }
    if visibility == Some(CssValue::Hide) {
        return visibility_hidden();
    }
    if ambiguous {
        SourceActivity::Ambiguous
    } else {
        SourceActivity::Active
    }
}

fn top_level_declarative_shadow_root(element: ElementRef<'_>) -> bool {
    if !is_html_element(element)
        || element.value().name() != "template"
        || !element.value().attr("shadowrootmode").is_some_and(|mode| {
            let mode = mode.trim_matches(['\t', '\n', '\u{000c}', '\r', ' ']);
            mode.eq_ignore_ascii_case("open") || mode.eq_ignore_ascii_case("closed")
        })
    {
        return false;
    }
    !element
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(|ancestor| is_html_element(ancestor) && ancestor.value().name() == "template")
}

fn html_void_name(name: &str) -> bool {
    matches!(
        name,
        "area" | "base" | "basefont" | "bgsound" | "br" | "col" | "embed" | "frame"
            | "hr" | "img" | "input" | "keygen" | "link" | "meta" | "param"
            | "source" | "track" | "wbr"
    )
}

/// A token-only preflight avoids constructing a tree for obvious excessive
/// depth or formatting counts. Tokenization respects quoted attributes,
/// comments and raw text. Complex insertion modes defer to the bounded real
/// parser instead of guessing their open-element stack.
struct SourceBudget {
    stack: RefCell<Vec<LocalName>>,
    tags: Cell<usize>,
    formatting: Cell<usize>,
    depth_trusted: Cell<bool>,
    exceeded: Cell<bool>,
    bypass: Cell<bool>,
    encoding_unreviewed: Cell<bool>,
}

impl SourceBudget {
    fn new() -> Self {
        Self {
            stack: RefCell::new(Vec::new()),
            tags: Cell::new(0),
            formatting: Cell::new(0),
            depth_trusted: Cell::new(true),
            exceeded: Cell::new(false),
            bypass: Cell::new(false),
            encoding_unreviewed: Cell::new(false),
        }
    }

    fn stop(&self) -> TokenSinkResult<()> {
        self.exceeded.set(true);
        TokenSinkResult::Script(())
    }
}

impl TokenSink for SourceBudget {
    type Handle = ();

    fn process_token(&self, token: Token, _line: u64) -> TokenSinkResult<()> {
        let Token::TagToken(tag) = token else {
            return TokenSinkResult::Continue;
        };
        let tags = self.tags.get() + 1;
        self.tags.set(tags);
        if tags > MAX_CHALLENGE_SOURCE_TAGS {
            return self.stop();
        }
        let name = tag.name.as_ref();
        if tag.kind == TagKind::StartTag {
            if name == "meta" {
                for attr in &tag.attrs {
                    if attr.name.local.as_ref() == "charset"
                        && !attr.value.eq_ignore_ascii_case("utf-8")
                        && !attr.value.eq_ignore_ascii_case("utf8")
                    {
                        self.encoding_unreviewed.set(true);
                    }
                    if attr.name.local.as_ref() == "http-equiv"
                        && attr.value.eq_ignore_ascii_case("content-type")
                    {
                        self.encoding_unreviewed.set(true);
                    }
                }
            }
            if matches!(name, "svg" | "math") {
                // Namespace/integration-point parsing requires the real tree
                // builder; its live stacks are bounded independently below.
                self.bypass.set(true);
                return TokenSinkResult::Script(());
            }
            if FORMATTING_ELEMENTS.contains(&name) {
                let formatting = self.formatting.get() + 1;
                self.formatting.set(formatting);
                if formatting > MAX_CHALLENGE_FORMATTING_STARTS {
                    return self.stop();
                }
            }
            if matches!(
                name,
                "p" | "li" | "dd" | "dt" | "option" | "optgroup" | "table" | "tr"
                    | "td" | "th" | "thead" | "tbody" | "tfoot" | "select" | "template"
            ) {
                self.depth_trusted.set(false);
            }
            if self.depth_trusted.get() && !html_void_name(name) {
                let mut stack = self.stack.borrow_mut();
                stack.push(tag.name.clone());
                if stack.len() > MAX_CHALLENGE_SOURCE_DEPTH {
                    return self.stop();
                }
            }
            return match name {
                "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                    TokenSinkResult::RawData(RawKind::Rawtext)
                }
                "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                "plaintext" => TokenSinkResult::Plaintext,
                _ => TokenSinkResult::Continue,
            };
        }
        if self.depth_trusted.get() {
            let mut stack = self.stack.borrow_mut();
            if stack.last().is_some_and(|open| open == &tag.name) {
                stack.pop();
            }
        }
        TokenSinkResult::Continue
    }
}

fn source_encoding_unreviewed(text: &str) -> bool {
    if !text.as_bytes().windows(4).any(|part| part.eq_ignore_ascii_case(b"meta")) {
        return false;
    }
    let input = BufferQueue::default();
    input.push_back(StrTendril::from_slice(text));
    let tokenizer = Tokenizer::new(SourceBudget::new(), Default::default());
    let _ = tokenizer.feed(&input);
    tokenizer.sink.encoding_unreviewed.get()
        || tokenizer.sink.bypass.get()
        || tokenizer.sink.exceeded.get()
}

/// On refusal, return the prefix before the token that exceeded the budget;
/// completed challenges in that earlier prefix can still be assessed.
fn source_prefix(text: &str) -> (&str, bool) {
    let input = BufferQueue::default();
    input.push_back(StrTendril::from_slice(text));
    let tokenizer = Tokenizer::new(SourceBudget::new(), Default::default());
    let _ = tokenizer.feed(&input);
    if tokenizer.sink.bypass.get() || !tokenizer.sink.exceeded.get() {
        return (text, true);
    }
    let mut remaining = 0usize;
    while let Some(part) = input.pop_front() {
        remaining += part.len();
    }
    let mut consumed = text.len().saturating_sub(remaining);
    while !text.is_char_boundary(consumed) {
        consumed -= 1;
    }
    // Truncating at the last '<' leaves the triggering tag incomplete even
    // when an attribute itself contains '<'.
    let end = text[..consumed].rfind('<').unwrap_or(0);
    (&text[..end], false)
}

struct LiveHandleCount(Cell<usize>);

impl Tracer for LiveHandleCount {
    type Handle = NodeId;

    fn trace_handle(&self, _node: &NodeId) {
        self.0.set(self.0.get() + 1);
    }
}

/// Observe html5ever's actual open-element and active-formatting stacks after
/// each small input chunk. This bounds even malformed or foreign HTML whose
/// tree-builder behavior the token-only preflight cannot safely predict.
fn bounded_challenge_document(text: &str) -> (Html, bool) {
    let mut parser = html5ever::driver::parse_document(
        HtmlTreeSink::new(Html::new_document()),
        Default::default(),
    );
    let source = StrTendril::from_slice(text);
    let mut start = 0usize;
    while start < text.len() {
        let mut end = (start + CHALLENGE_PARSE_CHUNK_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        parser.process(source.subtendril(start as u32, (end - start) as u32));
        let count = LiveHandleCount(Cell::new(0));
        parser.tokenizer.sink.trace_handles(&count);
        let nodes = parser.tokenizer.sink.sink.0.borrow().tree.nodes().len();
        if count.0.get() > MAX_CHALLENGE_DOM_DEPTH || nodes > MAX_CHALLENGE_DOM_ELEMENTS {
            // Reparse only the previously admitted prefix, whose live stacks
            // were bounded after every chunk. Do not consume the unsafe tail.
            return (Html::parse_document(&text[..start]), false);
        }
        start = end;
    }
    (parser.finish(), true)
}

struct ObservedTreeBuilder<F> {
    inner: TreeBuilder<NodeId, HtmlTreeSink>,
    observer: RefCell<F>,
}

impl<F: FnMut(&Token)> TokenSink for ObservedTreeBuilder<F> {
    type Handle = NodeId;

    fn process_token(&self, token: Token, line: u64) -> TokenSinkResult<NodeId> {
        (self.observer.borrow_mut())(&token);
        self.inner.process_token(token, line)
    }

    fn end(&self) { self.inner.end(); }

    fn adjusted_current_node_present_but_not_in_html_namespace(&self) -> bool {
        self.inner.adjusted_current_node_present_but_not_in_html_namespace()
    }
}

/// Parse a complete HTML source under the same byte, token, stack and node
/// budgets as challenge admission, observing the tokens fed to the native
/// tree builder. An exhausted budget never returns a partial document.
pub(crate) fn bounded_html_with_tokens<F: FnMut(&Token)>(text: &str, observer: F) -> Result<Html, ()> {
    let (text, bytes_complete) = bounded_text_prefix(text);
    let (text, token_complete) = token_work_prefix(text);
    let (text, source_complete) = source_prefix(text);
    if !(bytes_complete && token_complete && source_complete) { return Err(()); }

    let inner = TreeBuilder::new(HtmlTreeSink::new(Html::new_document()), Default::default());
    let tokenizer = Tokenizer::new(ObservedTreeBuilder { inner, observer: RefCell::new(observer) }, Default::default());
    let input = BufferQueue::default();
    let source = StrTendril::from_slice(text);
    let mut start = 0usize;
    while start < text.len() {
        let mut end = (start + CHALLENGE_PARSE_CHUNK_BYTES).min(text.len());
        while !text.is_char_boundary(end) { end -= 1; }
        input.push_back(source.subtendril(start as u32, (end - start) as u32));
        while let TokenizerResult::Script(_) = tokenizer.feed(&input) {}
        let count = LiveHandleCount(Cell::new(0));
        tokenizer.sink.inner.trace_handles(&count);
        let nodes = tokenizer.sink.inner.sink.0.borrow().tree.nodes().len();
        if count.0.get() > MAX_CHALLENGE_DOM_DEPTH || nodes > MAX_CHALLENGE_DOM_ELEMENTS { return Err(()); }
        start = end;
    }
    while let TokenizerResult::Script(_) = tokenizer.feed(&input) {}
    if !input.is_empty() { return Err(()); }
    tokenizer.end();
    let count = LiveHandleCount(Cell::new(0));
    tokenizer.sink.inner.trace_handles(&count);
    let nodes = tokenizer.sink.inner.sink.0.borrow().tree.nodes().len();
    if count.0.get() > MAX_CHALLENGE_DOM_DEPTH || nodes > MAX_CHALLENGE_DOM_ELEMENTS { return Err(()); }
    Ok(tokenizer.sink.inner.sink.finish())
}

/// Assess the retained source. The second value reports whether the whole
/// retained source was parsed: a truncated source cannot establish the
/// document-wide facts that decide candidate visibility.
fn assess_html_challenge(text: &str) -> (ChallengeAssessment, bool) {
    let (text, token_complete) = token_work_prefix(text);
    let (prefix, source_complete) = source_prefix(text);
    let (document, tree_complete) = bounded_challenge_document(prefix);
    // The retained source was parsed in full only when every budget held. A
    // truncated source cannot establish document-wide facts such as the
    // presence of an author stylesheet.
    let parse_complete = token_complete && source_complete && tree_complete;
    let Ok(all_elements) = Selector::parse("*") else {
        return (ChallengeAssessment::Unreviewed, false);
    };
    // Bound ancestor walks before stylesheet discovery or host analysis.
    for (index, element) in document.select(&all_elements).enumerate() {
        if index >= MAX_CHALLENGE_DOM_ELEMENTS
            || element
                .ancestors()
                .take(MAX_CHALLENGE_DOM_DEPTH + 1)
                .count()
                > MAX_CHALLENGE_DOM_DEPTH
        {
            return (ChallengeAssessment::Unreviewed, false);
        }
    }
    let mut shadow_hosts = HashSet::new();
    let mut unreviewed = !token_complete || !source_complete || !tree_complete;
    for element in document.select(&all_elements) {
        if top_level_declarative_shadow_root(element) {
            unreviewed = true;
            if let Some(host) = element.parent().and_then(ElementRef::wrap) {
                shadow_hosts.insert(host.id());
            }
        }
    }
    let stylesheet_present = author_stylesheet_present(&document);
    let mut disabled_fieldsets: HashMap<NodeId, Option<NodeId>> = HashMap::new();
    for element in document.select(&all_elements) {
        if !is_html_element(element) {
            continue;
        }
        if !inert_ancestor(element) {
            let value = element.value();
            let review_cue = (value.name() == "iframe" && value.attr("srcdoc").is_some())
                || ["placeholder", "title", "aria-label", "aria-description"]
                    .into_iter()
                    .filter_map(|name| value.attr(name))
                    .any(|text| challenge_marker_matches(text)
                        || text.to_ascii_lowercase().contains("verification code"))
                || value.attr("autocomplete").is_some_and(|text| {
                    text.split_ascii_whitespace().any(|token| token.eq_ignore_ascii_case("one-time-code"))
                })
                || (value.name() == "label"
                    && challenge_marker_matches(&active_element_text(element)));
            if review_cue {
                unreviewed = true;
            }
        }
        if element.value().name() == "fieldset" && element.value().attr("disabled").is_some() {
            let first_legend = element
                .children()
                .filter_map(ElementRef::wrap)
                .find(|child| is_html_element(*child) && child.value().name() == "legend");
            disabled_fieldsets.insert(element.id(), first_legend.map(|legend| legend.id()));
        }
        let value = element.value();
        let button_cue = if value.name() == "button" {
            let mut text = String::new();
            visit_active_text(element, |_| false, |part| {
                text.push_str(part);
                false
            });
            Some(std::borrow::Cow::Owned(text))
        } else if value.name() == "input"
            && value.attr("type").is_some_and(|kind| {
                ["button", "submit", "reset"].iter().any(|name| kind.eq_ignore_ascii_case(name))
            })
        {
            value.attr("value").map(std::borrow::Cow::Borrowed)
        } else {
            None
        };
        if button_cue.as_deref().is_some_and(challenge_text_cue)
            && challenge_activity(element, &disabled_fieldsets, stylesheet_present) != SourceActivity::Inert
        {
            unreviewed = true;
        }
        if !challenge_candidate(element) {
            continue;
        }
        if shadow_hosts.contains(&element.id())
            || element.ancestors().any(|ancestor| shadow_hosts.contains(&ancestor.id()))
        {
            // scraper leaves light DOM under the host; the browser's shadow
            // tree and slots determine whether it is actually rendered.
            unreviewed = true;
            continue;
        }
        match challenge_activity(element, &disabled_fieldsets, stylesheet_present) {
            SourceActivity::Active => return (ChallengeAssessment::Detected, parse_complete),
            SourceActivity::Inert => {}
            SourceActivity::Ambiguous => unreviewed = true,
        }
    }
    if unreviewed {
        (ChallengeAssessment::Unreviewed, false)
    } else {
        (ChallengeAssessment::Clear, parse_complete)
    }
}

/// Script/style/template/noscript payloads are not source prose.
pub(crate) fn element_text(element: ElementRef<'_>) -> String {
    if inert_element(element) {
        return String::new();
    }
    active_element_text(element)
}

/// Linear DOM walk after the caller has checked the outer context; no ancestor
/// rescans or subtree copies, including for active image-only attachment links.
pub(crate) fn active_element_text(element: ElementRef<'_>) -> String {
    let mut output = String::new();
    let _ = visit_active_text(
        element,
        |_| false,
        |text| {
            for word in text.split_whitespace() {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(word);
            }
            false
        },
    );
    output
}

/// Visit active text nodes in document order, stopping when the visitor returns
/// true. Callers can add source-specific inertness without copying subtrees.
pub(crate) fn visit_active_text(
    element: ElementRef<'_>,
    should_skip: impl Fn(ElementRef<'_>) -> bool,
    visit: impl FnMut(&str) -> bool,
) -> bool {
    visit_text(
        element,
        |element| is_inert_text_element(element) || should_skip(element),
        visit,
    )
}

/// Walk text with caller-owned subtree exclusions. Directionality and source
/// prose use different rules, notably for HTML noscript text.
pub(crate) fn visit_text(
    element: ElementRef<'_>,
    should_skip: impl Fn(ElementRef<'_>) -> bool,
    mut visit: impl FnMut(&str) -> bool,
) -> bool {
    if should_skip(element) {
        return false;
    }
    let root = element.id();
    let mut current = element.first_child();
    while let Some(node) = current {
        let skip = ElementRef::wrap(node).is_some_and(&should_skip);
        if let Node::Text(text) = node.value()
            && visit(&text.text)
        {
            return true;
        }
        if !skip && let Some(child) = node.first_child() {
            current = Some(child);
            continue;
        }
        let mut cursor = node;
        loop {
            if let Some(sibling) = cursor.next_sibling() {
                current = Some(sibling);
                break;
            }
            match cursor.parent() {
                Some(parent) if parent.id() != root => cursor = parent,
                _ => {
                    current = None;
                    break;
                }
            }
        }
    }
    false
}

fn is_inert_text_element(element: ElementRef<'_>) -> bool {
    is_inert_context(element)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ScriptKind {
    Classic,
    Module,
}

pub(crate) const MAX_SCRIPT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SCRIPT_DEPTH: usize = 128;

fn script_line_end(bytes: &[u8], offset: usize) -> usize {
    if bytes
        .get(offset)
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return 1;
    }
    if matches!(
        bytes.get(offset..offset + 3),
        Some([0xe2, 0x80, 0xa8 | 0xa9])
    ) {
        return 3;
    }
    0
}

/// Bounded recognizers share classic-script comment and line-ending rules.
/// This skips trivia only; it does not evaluate JavaScript.
pub(crate) fn script_trivia(bytes: &[u8], offset: &mut usize) -> Option<()> {
    loop {
        while let Some(byte) = bytes.get(*offset) {
            let line_end = script_line_end(bytes, *offset);
            if !byte.is_ascii_whitespace() && line_end == 0 {
                break;
            }
            *offset += line_end.max(1);
        }
        if bytes.get(*offset..*offset + 2) == Some(b"//")
            || bytes.get(*offset..*offset + 4) == Some(b"<!--")
        {
            while *offset < bytes.len() && script_line_end(bytes, *offset) == 0 {
                *offset += 1;
            }
        } else if bytes.get(*offset..*offset + 3) == Some(b"-->") {
            let mut start = *offset;
            while start > 0
                && bytes[start - 1].is_ascii_whitespace()
                && !matches!(bytes[start - 1], b'\r' | b'\n')
            {
                start -= 1;
            }
            if start != 0 && !matches!(bytes[start - 1], b'\r' | b'\n') {
                return None;
            }
            while *offset < bytes.len() && script_line_end(bytes, *offset) == 0 {
                *offset += 1;
            }
        } else if bytes.get(*offset..*offset + 2) == Some(b"/*") {
            *offset += 2;
            while bytes.get(*offset..*offset + 2) != Some(b"*/") {
                if *offset >= bytes.len() {
                    return None;
                }
                *offset += 1;
            }
            *offset += 2;
        } else {
            return Some(());
        }
    }
}

pub(crate) fn script_quoted_end(bytes: &[u8], offset: &mut usize) -> Option<()> {
    let quote = *bytes.get(*offset)?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }
    *offset += 1;
    while let Some(byte) = bytes.get(*offset) {
        *offset += 1;
        if *byte == quote {
            return Some(());
        }
        if quote == b'`' && *byte == b'$' && bytes.get(*offset) == Some(&b'{') {
            return None;
        }
        if *byte == b'\\' {
            if *offset == bytes.len() {
                return None;
            }
            *offset += 1;
        }
    }
    None
}

pub(crate) fn script_kind(element: ElementRef<'_>) -> Option<ScriptKind> {
    let explicit_type = element.value().attr("type");
    // An explicit empty type still takes precedence over the legacy language.
    if explicit_type.is_none()
        && element.value().attr("language").is_some_and(|language| {
            !language.is_empty() && !language.eq_ignore_ascii_case("javascript")
        })
    {
        return None;
    }
    let kind = explicit_type
        .unwrap_or_default()
        .trim_matches(|ch| matches!(ch, '\t' | '\n' | '\u{000c}' | '\r' | ' '));
    if kind.eq_ignore_ascii_case("module") {
        Some(ScriptKind::Module)
    } else if kind.is_empty()
        || [
            "text/javascript",
            "application/javascript",
            "text/ecmascript",
            "application/ecmascript",
            "application/x-javascript",
        ]
        .iter()
        .any(|allowed| kind.eq_ignore_ascii_case(allowed))
    {
        Some(ScriptKind::Classic)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scraper::{Html, Selector};

    #[test]
    fn script_trivia_keeps_existing_line_endings_and_comment_boundaries() {
        for line_end in ["\r", "\n", "\u{2028}", "\u{2029}"] {
            let source = format!(" \t/* bounded */ // ignored{line_end}target");
            let mut offset = 0;
            assert_eq!(script_trivia(source.as_bytes(), &mut offset), Some(()));
            assert_eq!(&source[offset..], "target");
        }
        for source in ["<!-- ignored\n target", "\r\n \t--> ignored\n target"] {
            let mut offset = 0;
            assert_eq!(script_trivia(source.as_bytes(), &mut offset), Some(()));
            assert_eq!(&source[offset..], "target");
        }
        for (source, mut offset) in [("/* unterminated", 0), ("x --> ignored\n target", 2)] {
            assert_eq!(script_trivia(source.as_bytes(), &mut offset), None);
        }
    }

    #[test]
    fn script_quoted_end_skips_literals_but_rejects_active_interpolation() {
        for source in [
            r#""value\"still";target"#,
            r#"'value\'still';target"#,
            r#"`value\`still`;target"#,
        ] {
            let mut offset = 0;
            assert_eq!(script_quoted_end(source.as_bytes(), &mut offset), Some(()));
            assert_eq!(&source[offset..], ";target");
        }
        for source in [r#""unterminated"#, r#"'trailing\"#, "`active${call()}`", "not quoted"] {
            let mut offset = 0;
            assert_eq!(script_quoted_end(source.as_bytes(), &mut offset), None);
        }
    }

    fn element_by_id<'a>(document: &'a Html, all: &Selector, id: &str) -> ElementRef<'a> {
        document
            .select(all)
            .find(|element| element.value().attr("id") == Some(id))
            .expect("element id")
    }

    fn html_assessment(body: &str) -> ChallengeAssessment {
        assess_challenge_body(body.as_bytes(), Some("text/html"), true)
    }

    #[test]
    fn truncated_challenge_scans_first_tail_attributes_and_comment_ends() {
        for (tail, expected) in [
            (r#"<link rel=stylesheet rel=alternate>"#, ChallengeAssessment::Unreviewed),
            (r#"<link rel=alternate rel=stylesheet>"#, ChallengeAssessment::Detected),
            (r#"<link rel rel=stylesheet>"#, ChallengeAssessment::Detected),
            (r#"<link rel='style&amp;sheet'>"#, ChallengeAssessment::Unreviewed),
            (r#"<link rel=stylesheet"#, ChallengeAssessment::Unreviewed),
            (r#"<!-- ' --> <style>input {display:none}</style>"#, ChallengeAssessment::Unreviewed),
            (r#"<!-- \" --!> <style>input {display:none}</style>"#, ChallengeAssessment::Unreviewed),
            (r#"<!-- ' --> <p>ordinary</p>"#, ChallengeAssessment::Detected),
            (r#"<!-- unterminated"#, ChallengeAssessment::Unreviewed),
            (r#"<meta charset=shift_jis charset=utf-8>"#, ChallengeAssessment::Unreviewed),
            (r#"<meta charset=utf-8 charset=shift_jis>"#, ChallengeAssessment::Detected),
            (r#"<meta charset charset=shift_jis>"#, ChallengeAssessment::Unreviewed),
            (r#"<meta http-equiv=content-type http-equiv=refresh>"#, ChallengeAssessment::Unreviewed),
            (r#"<meta http-equiv=refresh http-equiv=content-type>"#, ChallengeAssessment::Detected),
            (r#"<meta http-equiv http-equiv=content-type>"#, ChallengeAssessment::Detected),
        ] {
            let mut body = b"<input name=captcha>\xff".to_vec();
            body.extend_from_slice(tail.as_bytes());
            assert_eq!(assess_challenge_body(&body, Some("text/html"), true), expected, "{tail}");
        }
    }

    #[test]
    fn truncated_challenge_reconsumes_invalid_tag_open_in_tail() {
        let prefix = format!("<input name=captcha>{}", "<a></a>".repeat(MAX_CHALLENGE_FORMATTING_STARTS + 1));
        for (tail, expected) in [
            ("<<style>input { display:none }</style>", ChallengeAssessment::Unreviewed),
            ("< <style>input { display:none }</style>", ChallengeAssessment::Unreviewed),
            ("<0<style>input { display:none }</style>", ChallengeAssessment::Unreviewed),
            ("<<<link rel=stylesheet href=x>", ChallengeAssessment::Unreviewed),
            ("<<meta charset=shift_jis>", ChallengeAssessment::Unreviewed),
            ("<<span>ordinary</span>", ChallengeAssessment::Detected),
            ("<0<span>ordinary</span>", ChallengeAssessment::Detected),
            (r#"</0 a="><style>input{display:none}</style>"#, ChallengeAssessment::Unreviewed),
            (r#"<?bogus a="><style>input{display:none}</style>"#, ChallengeAssessment::Unreviewed),
            (r#"<!bogus a="><style>input{display:none}</style>"#, ChallengeAssessment::Unreviewed),
            (r#"<svg><![CDATA[><fake a="]]></svg><style>input{display:none}</style>"#, ChallengeAssessment::Unreviewed),
            ("<![CDATA[unfinished", ChallengeAssessment::Unreviewed),
            (r#"</0 a="><span>ordinary</span>"#, ChallengeAssessment::Detected),
            ("<!doctype html><p>ordinary</p>", ChallengeAssessment::Detected),
            (r#"<!DOCTYPE html SYSTEM "about:legacy-compat"><p>ordinary</p>"#, ChallengeAssessment::Detected),
            ("<!-- <style> ignored --> <p>ordinary</p>", ChallengeAssessment::Detected),
            (r#"<!doctype html SYSTEM "broken><style>input{display:none}</style>"#, ChallengeAssessment::Unreviewed),
        ] {
            let body = format!("{prefix}{tail}");
            assert_eq!(html_assessment(&body), expected, "{tail}");
        }
    }

    #[test]
    fn popovers_and_button_text_are_review_cues_not_confirmation() {
        for body in [
            r#"<input name=captcha popover>"#,
            r#"<div popover=manual><input name=captcha></div>"#,
            r#"<button>Enter CAPTCHA</button>"#,
            r#"<button>Verification code</button>"#,
            r#"<button>CAP<span>TCHA</span></button>"#,
            r#"<button>Verifi<span>cation </span>code</button>"#,
            "<button>Verification\n  code</button>",
            "<button>Verification\t<span>code</span></button>",
            "<input type=submit value='Verification\n code'>",
            r#"<button>验<span>证</span>码</button>"#,
            r#"<button>校<span>验</span>码</button>"#,
            r#"<input type=submit value='CAPTCHA'>"#,
            r#"<input type=button value='Verification code'>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Unreviewed, "{body}");
        }
        for body in [
            r#"<button disabled>CAPTCHA</button>"#,
            r#"<button disabled>CAP<span>TCHA</span></button>"#,
            "<button disabled>Verification\n code</button>",
            r#"<fieldset disabled><button>CAPTCHA</button></fieldset>"#,
            r#"<div inert><button>CAPTCHA</button></div>"#,
            r#"<div inert><button>验<span>证</span>码</button></div>"#,
            "<div inert><button>Verification\tcode</button></div>",
            r#"<div inert popover><input name=captcha></div>"#,
            r#"<template><button>CAPTCHA</button></template>"#,
            r#"<input type=submit disabled value=CAPTCHA>"#,
            r#"<input type=text value=CAPTCHA>"#,
            r#"<p>CAPTCHA verification code</p>"#,
            r#"<button>Continue</button>"#,
            r#"<button>Con<span>tinue</span></button>"#,
            r#"<button>CAP<span>able</span></button>"#,
            "<button>Continue\n  normally</button>",
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Clear, "{body}");
        }
        for body in [
            r#"<input name=captcha>"#,
            r#"<svg popover><foreignObject><input name=captcha></foreignObject></svg>"#,
            r#"<button name=captcha>CAPTCHA</button>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Detected, "{body}");
        }
    }

    #[test]
    fn declared_charset_shares_quoted_parameter_rules() {
        assert_eq!(declared_html_charset("text/html; boundary=\"a;b\""), Ok(None));
        assert_eq!(declared_html_charset(r#"text/html; charset="ut\f-8"; charset=UTF-8"#).unwrap().as_deref(), Some("UTF-8"));
        assert_eq!(declared_html_charset("text/html; charset=shift_jis").unwrap().as_deref(), Some("shift_jis"));
        for mime in ["text/html; charset=utf-8; charset=shift_jis", "text/html; charset=", "text/html; charset=\"utf-8", "text/html; bad"] {
            assert_eq!(declared_html_charset(mime), Err(()), "{mime}");
        }
    }

    #[test]
    fn challenge_assessment_detects_active_html_controls_actions_and_widgets() {
        for body in [
            r#"<form action="/captcha"><input name="ordinary"></form>"#,
            r#"<iframe src="https://example.invalid/recaptcha/anchor"></iframe>"#,
            r#"<iframe src="/turnstile"></iframe>"#,
            r#"<input name="captcha">"#,
            r#"<textarea id="verification-code"></textarea>"#,
            r#"<select name="challenge"></select>"#,
            r#"<button autocomplete="verification_code">Continue</button>"#,
            r#"<div class="g-recaptcha"></div>"#,
            r#"<div class="h-captcha"></div>"#,
            r#"<div class="cf-turnstile"></div>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Detected, "{body}");
        }
    }

    #[test]
    fn challenge_assessment_respects_disabled_hidden_and_first_legend() {
        for body in [
            r#"<input name="captcha" disabled>"#,
            r#"<input name="captcha" type="hidden">"#,
            r#"<span hidden><input name="captcha"></span>"#,
            r#"<span inert><input name="captcha"></span>"#,
            r#"<fieldset disabled><input name="captcha"></fieldset>"#,
            r#"<fieldset disabled><legend>caption</legend><legend><input name="captcha"></legend></fieldset>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Clear, "{body}");
        }
        assert_eq!(
            html_assessment(
                r#"<fieldset disabled><legend><span><input name="captcha"></span></legend></fieldset>"#,
            ),
            ChallengeAssessment::Detected
        );
        // A form's associated controls need not be its descendants.
        for body in [
            r#"<form id="f" action="/captcha" hidden></form><button form="f">Go</button>"#,
            r#"<form id="f" action="/captcha" inert></form><button form="f">Go</button>"#,
            r#"<form id="f" action="/captcha" style="display:none"></form><button form="f">Go</button>"#,
            r#"<div class="cf-turnstile" style="visibility:hidden"><span style="visibility:visible">widget</span></div>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Unreviewed, "{body}");
        }
    }

    #[test]
    fn challenge_assessment_respects_css_cascade_and_quoted_declarations() {
        assert_eq!(
            html_assessment(r#"<input name="captcha" style="display:none">"#),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            html_assessment(r#"<input name="captcha" style="display:none !important">"#),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            html_assessment(r#"<input name="captcha" style="visibility:hidden">"#),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            html_assessment(r#"<span style="display:none"><input name="captcha"></span>"#),
            ChallengeAssessment::Clear
        );
        // A later declaration of the same property wins the cascade, so the
        // control is displayed and remains an active challenge.
        assert_eq!(
            html_assessment(r#"<input name="captcha" style="display:none;display:block">"#),
            ChallengeAssessment::Detected
        );
        // Quoted text inside a custom property is not a display declaration.
        assert_eq!(
            html_assessment(r#"<input name="captcha" style="--example:';display:none;'">"#),
            ChallengeAssessment::Detected
        );
        for body in [
            r#"<input name="captcha" style="--example:{a;display:none;}">"#,
            r#"<input name="captcha" style="--example:[a;display:none;]">"#,
            r#"<input name="captcha" style="--example:var(--x;display:none;)">"#,
            r#"<input name="captcha" style="--example:\;display:none;">"#,
            r#"<input name="captcha" hidden style="display:block">"#,
            r#"<div style="visibility:hidden"><span style="visibility:visible"><input name="captcha"></span></div>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Detected, "{body}");
        }
        for body in [
            r#"<input name="captcha" style="display:var(--challenge-display)">"#,
            r#"<div style="content-visibility:env(--challenge)"><iframe src="/captcha"></iframe></div>"#,
            r#"<input name="captcha" style="display:none/* unterminated">"#,
            r#"<input name="captcha" style="display:inherit">"#,
            r#"<input name="captcha" style="display:none;d\69 splay:block">"#,
            r#"<input name="captcha" style="--example:(;display:none;">"#,
            r#"<input name="captcha" style="display:none;all:initial">"#,
            r#"<input name="captcha" style="display:&#160;none">"#,
            r#"<input name="captcha" style="opacity:0">"#,
        ] {
            assert_eq!(
                html_assessment(body),
                ChallengeAssessment::Unreviewed,
                "{body}"
            );
        }
    }

    #[test]
    fn challenge_assessment_reviews_stylesheet_dependent_candidates() {
        for body in [
            r#"<style>input { display:none }</style><input name="captcha">"#,
            r#"<link rel="stylesheet" href="/site.css"><input name="captcha">"#,
            r#"<style>input { visibility:visible }</style><div style="visibility:hidden !important"><input name="captcha"></div>"#,
        ] {
            assert_eq!(
                html_assessment(body),
                ChallengeAssessment::Unreviewed,
                "{body}"
            );
        }
        // A disabled control is inactive whatever the stylesheet says.
        assert_eq!(
            html_assessment(
                r#"<style>input { display:none }</style><input name="captcha" disabled>"#
            ),
            ChallengeAssessment::Clear
        );
        // An important inline hiding declaration outranks an author rule.
        assert_eq!(
            html_assessment(
                r#"<style>input { display:block }</style><input name="captcha" style="display:none !important">"#
            ),
            ChallengeAssessment::Clear
        );
        // A stylesheet inside an inert template never applies to the document.
        assert_eq!(
            html_assessment(
                r#"<template><style>input { display:none }</style></template><input name="captcha">"#,
            ),
            ChallengeAssessment::Detected
        );
    }

    #[test]
    fn challenge_assessment_skips_templates_prose_comments_and_foreign_lookalikes() {
        for body in [
            r#"<script>const source = '<input name="captcha">';</script>"#,
            r#"<noscript><input name="captcha"></noscript>"#,
            r#"<template><input name="captcha"><div class="cf-turnstile"></div></template>"#,
            r#"<!-- <form action="/captcha"></form> --><p>challenge and captcha prose</p>"#,
            r#"<svg><g class="cf-turnstile"></g><text>captcha</text></svg>"#,
            r#"<math><iframe src="/challenge"></iframe></math>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Clear, "{body}");
        }
        // A div inside foreign content breaks out into HTML and is a widget.
        assert_eq!(
            html_assessment(r#"<svg><input name="captcha"/><div class="cf-turnstile"></div></svg>"#),
            ChallengeAssessment::Detected
        );
    }

    #[test]
    fn challenge_assessment_reviews_declarative_shadow_roots_without_latching_nested_templates() {
        for mode in ["open", "closed"] {
            let body = format!(
                r#"<div><template shadowrootmode="{mode}"><input name="captcha"></template></div>"#
            );
            assert_eq!(html_assessment(&body), ChallengeAssessment::Unreviewed);
            let separate = format!(r#"<input name="captcha">{body}"#);
            assert_eq!(html_assessment(&separate), ChallengeAssessment::Detected);
            for contents in [
                r#"<template shadowrootmode="open"></template><input name="captcha">"#,
                r#"<input name="captcha"><template shadowrootmode="open"></template>"#,
                r#"<template shadowrootmode="open"><slot></slot></template><input name="captcha">"#,
            ] {
                let host = format!("<div>{contents}</div>");
                assert_eq!(html_assessment(&host), ChallengeAssessment::Unreviewed);
                let independent = format!("{host}<input name='captcha'>");
                assert_eq!(html_assessment(&independent), ChallengeAssessment::Detected);
            }
        }
        assert_eq!(
            html_assessment(
                r#"<template><template shadowrootmode="open"><input name="captcha"></template></template>"#,
            ),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            html_assessment(
                r#"<svg><template><foreignObject><div><template shadowrootmode="open"><input name="captcha"></template></div></foreignObject></template></svg>"#,
            ),
            ChallengeAssessment::Unreviewed
        );
    }

    #[test]
    fn challenge_assessment_never_parses_valid_json_html_strings() {
        for mime in ["application/json", "application/problem+json"] {
            for body in [
                r#"{"markup":"<input name='captcha'><div class='cf-turnstile'></div>"}"#,
                r#"{"markup":"<!doctype html><html><body><form action='/captcha'></form></body></html>"}"#,
            ] {
                assert_eq!(
                    assess_challenge_body(body.as_bytes(), Some(mime), true),
                    ChallengeAssessment::Clear,
                    "{mime}"
                );
            }
        }
        assert_eq!(
            assess_challenge_body(
                br#"Source example: <input name="captcha">"#,
                Some("text/plain"),
                true,
            ),
            ChallengeAssessment::Clear
        );
        // The ignored-any syntax scan alone does not establish UTF-8 validity.
        assert_eq!(
            assess_challenge_body(b"{\"x\":\"\xff\"}", Some("application/json"), true),
            ChallengeAssessment::Unreviewed
        );
        let large = format!(
            "{{\"markup\":\"<input name=captcha>\",\"padding\":\"{}\"}}",
            "x".repeat(MAX_CHALLENGE_BYTES + 1)
        );
        for mime in [None, Some("text/*")] {
            assert_eq!(
                assess_challenge_body(large.as_bytes(), mime, true),
                ChallengeAssessment::Unreviewed
            );
        }
        assert_eq!(
            assess_challenge_body(large.as_bytes(), Some("application/json"), true),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            assess_challenge_body(br#"{"markup":"<input name=captcha>"#, None, false),
            ChallengeAssessment::Unreviewed
        );
    }

    #[test]
    fn challenge_assessment_admits_complete_binary_originals_without_utf8() {
        use base64::Engine;
        let png = base64::engine::general_purpose::STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aO2cAAAAASUVORK5CYII=")
            .expect("embedded one-pixel PNG");
        let mut pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n".to_vec();
        let mut offsets = Vec::new();
        for object in [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>\nendobj\n",
        ] {
            offsets.push(pdf.len());
            pdf.extend_from_slice(object.as_bytes());
        }
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        let blob = b"\x00\xffopaque git blob <html><input name=captcha>";
        for (mime, bytes) in [
            ("image/png", png.as_slice()),
            ("application/pdf", pdf.as_slice()),
            ("application/vnd.github.raw+json", pdf.as_slice()),
            ("application/octet-stream", blob.as_slice()),
        ] {
            assert!(std::str::from_utf8(bytes).is_err());
            assert_eq!(
                assess_challenge_body(bytes, Some(mime), true),
                ChallengeAssessment::Clear
            );
            assert_eq!(
                assess_challenge_body(bytes, Some(mime), false),
                ChallengeAssessment::Unreviewed
            );
            assert_eq!(
                assess_challenge_body(bytes, None, true),
                ChallengeAssessment::Unreviewed
            );
        }
        for bytes in [
            b"<!doctype html><html><input name=captcha>".as_slice(),
            b" \n<!-- preface -->\n<html><input name=captcha>".as_slice(),
            b"<!--x--!><html><input name=captcha>".as_slice(),
            b"<!--><html><input name=captcha><!--tail-->".as_slice(),
            b"<!---><html><input name=captcha><!--tail-->".as_slice(),
        ] {
            for mime in ["application/pdf", "application/vnd.github.raw+json"] {
                assert_eq!(
                    assess_challenge_body(bytes, Some(mime), true),
                    ChallengeAssessment::Unreviewed
                );
            }
        }
    }

    #[test]
    fn challenge_assessment_validates_json_beyond_html_budget() {
        let json = format!("{{\"data\":\"{}\"}}", "x".repeat(MAX_CHALLENGE_BYTES + 1));
        assert_eq!(
            assess_challenge_body(json.as_bytes(), Some("application/json"), true),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            assess_challenge_body(json.as_bytes(), Some("application/json"), false),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"{invalid json}", Some("application/json"), true),
            ChallengeAssessment::Unreviewed
        );
    }

    #[test]
    fn challenge_assessment_limits_raw_json_exception_to_github_blob_media_type() {
        for body in [
            b"plain non-JSON blob".as_slice(),
            b"%PDF-1.4\n%\xff\n%%EOF\n".as_slice(),
        ] {
            assert_eq!(
                assess_challenge_body(body, Some("application/vnd.github.raw+json"), true),
                ChallengeAssessment::Clear
            );
            assert_eq!(
                assess_challenge_body(body, Some("application/vnd.github.raw+json"), false),
                ChallengeAssessment::Unreviewed
            );
            for mime in ["application/problem+json", "application/vnd.example.raw+json"] {
                assert_eq!(
                    assess_challenge_body(body, Some(mime), true),
                    ChallengeAssessment::Unreviewed
                );
            }
        }
        assert_eq!(
            assess_challenge_body(
                b"<!doctype html><html><input name=captcha>",
                Some("application/vnd.github.raw+json"),
                true,
            ),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(
                br#"{"type":"synthetic"}"#,
                Some("application/problem+json"),
                true,
            ),
            ChallengeAssessment::Clear
        );
    }

    #[test]
    fn challenge_assessment_scans_valid_utf8_prefix_and_fails_closed() {
        let mut complete_then_invalid = b"<form><input name='captcha'></form>".to_vec();
        complete_then_invalid.extend_from_slice(&[0xff, b'<']);
        assert_eq!(
            assess_challenge_body(&complete_then_invalid, Some("text/html"), true),
            ChallengeAssessment::Detected
        );

        let mut invalid_before_unknown = b"<p>ordinary</p>".to_vec();
        invalid_before_unknown.extend_from_slice(&[0xff]);
        invalid_before_unknown.extend_from_slice(b"<input name='captcha'>");
        assert_eq!(
            assess_challenge_body(&invalid_before_unknown, Some("text/html"), true),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"\xff<input name='captcha'>", Some("text/html"), true),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"\xff<input name='captcha'>", Some("text/plain"), true),
            ChallengeAssessment::Clear
        );
    }

    #[test]
    fn challenge_assessment_distinguishes_partial_reads_from_complete_documents() {
        assert_eq!(
            assess_challenge_body(b"<input name='captcha'>", Some("text/html"), false),
            ChallengeAssessment::Detected
        );
        assert_eq!(
            assess_challenge_body(b"<div class='cf-turnstile'>", Some("text/html"), false),
            ChallengeAssessment::Detected
        );
        for body in [
            b"<p>ordinary</p>".as_slice(),
            b"<input name='captcha'".as_slice(),
            b"<div class='cf-turnstile'".as_slice(),
        ] {
            assert_eq!(
                assess_challenge_body(body, Some("text/html"), false),
                ChallengeAssessment::Unreviewed
            );
        }
        assert_eq!(
            assess_challenge_body(b"<p>ordinary</p>", Some("text/html"), true),
            ChallengeAssessment::Clear
        );
        assert_eq!(
            assess_challenge_body(b"<input name='captcha'>", Some("text/plain"), false),
            ChallengeAssessment::Unreviewed
        );
    }

    #[test]
    fn challenge_assessment_handles_missing_ambiguous_and_mismatched_mime() {
        let document = br#"<!doctype html><html><body><input name="captcha"></body></html>"#;
        for mime in [
            "application/xhtml+xml",
            "text/plain",
            "application/json",
            "application/octet-stream",
        ] {
            assert_eq!(
                assess_challenge_body(document, Some(mime), true),
                ChallengeAssessment::Unreviewed,
                "{mime}"
            );
        }
        assert_eq!(
            assess_challenge_body(b"<p>ordinary</p>", None, true),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"<input name='captcha'>", None, true),
            ChallengeAssessment::Detected
        );
        assert_eq!(
            assess_challenge_body(b"<p>ordinary</p>", Some("text/*"), true),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"<input name='captcha'>", Some("text/*"), true),
            ChallengeAssessment::Detected
        );
    }

    #[test]
    fn challenge_assessment_refuses_unsupported_and_conflicting_charsets() {
        let utf16: Vec<u8> = "<input name='captcha'>"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert!(std::str::from_utf8(&utf16).is_ok());
        assert_eq!(
            assess_challenge_body(&utf16, Some("text/html; charset=utf-16le"), true),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(
                b"<input name='captcha'>",
                Some("text/html; charset=gbk"),
                true,
            ),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(
                b"<input name='captcha'>",
                Some("text/html; charset=utf-8; charset=gbk"),
                true,
            ),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"<input name='captcha'>", Some("text/html; charset="), true),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(b"<input name='captcha'>", Some("text/html; charset"), true),
            ChallengeAssessment::Unreviewed
        );
        for mime in [
            "text/html; charset us-ascii",
            "text/html; charset us-ascii=utf-8",
            "text/html; charset=us-ascii",
            "text/html; charset=\u{00a0}utf-8",
            "text/html; charset\u{00a0}=utf-8",
        ] {
            assert_eq!(
                assess_challenge_body(b"<input name='captcha'>", Some(mime), true),
                ChallengeAssessment::Unreviewed,
                "{mime}"
            );
        }
        assert_eq!(
            assess_challenge_body(
                b"<input name='captcha'>",
                Some("text/html; charset=utf-8"),
                true,
            ),
            ChallengeAssessment::Detected
        );
        assert_eq!(
            assess_challenge_body(
                b"<input name='captcha'>",
                Some("text/html; charset=utf8"),
                true,
            ),
            ChallengeAssessment::Detected
        );
        for mime in [
            r#"text/html; note="a;charset=gbk;b"; charset=utf-8"#,
            r#"text/html; note="x\";charset=gbk;y"; charset="utf-8""#,
        ] {
            assert_eq!(
                assess_challenge_body(b"<p>ordinary</p>", Some(mime), true),
                ChallengeAssessment::Clear,
                "{mime}"
            );
            assert_eq!(
                assess_challenge_body(b"<input name=captcha>", Some(mime), true),
                ChallengeAssessment::Detected,
                "{mime}"
            );
        }
        assert_eq!(
            assess_challenge_body(
                b"<input name=captcha>",
                Some("text/html; note=\"unterminated;charset=utf-8"),
                true,
            ),
            ChallengeAssessment::Unreviewed
        );
        // NUL-separated ASCII is valid UTF-8 but is ambiguous as HTML bytes.
        assert_eq!(
            assess_challenge_body(
                b"<i\0n\0p\0u\0t\0 \0n\0a\0m\0e\0=\0'\0c\0a\0p\0t\0c\0h\0a\0'\0>",
                Some("text/html; charset=utf-8"),
                true,
            ),
            ChallengeAssessment::Unreviewed
        );
    }

    #[test]
    fn challenge_assessment_bounds_source_complexity_before_parsing() {
        let many_formatting = "<b id=\"x\">".repeat(MAX_CHALLENGE_FORMATTING_STARTS + 1);
        assert_eq!(html_assessment(&many_formatting), ChallengeAssessment::Unreviewed);
        for prefix in ["", "<!--x--!>"] {
            let self_closing = format!(
                "{prefix}{}",
                (0..=MAX_CHALLENGE_FORMATTING_STARTS)
                    .map(|id| format!("<b id=\"{id}\"/>"))
                    .collect::<String>()
            );
            assert!(!source_prefix(&self_closing).1);
        }
        let foreign = format!(
            "<svg><script>{}",
            (0..=MAX_CHALLENGE_FORMATTING_STARTS)
                .map(|id| format!("<b id=\"{id}\"/>"))
                .collect::<String>()
        );
        assert_eq!(html_assessment(&foreign), ChallengeAssessment::Unreviewed);
        let paired = "<b></b>".repeat(MAX_CHALLENGE_FORMATTING_STARTS + 1);
        assert!(!source_prefix(&paired).1);
        let many_tags = "<span></span>".repeat(MAX_CHALLENGE_SOURCE_TAGS / 2 + 1);
        assert_eq!(html_assessment(&many_tags), ChallengeAssessment::Unreviewed);
        let many_closings = "</u>".repeat(MAX_CHALLENGE_SOURCE_TAGS + 1);
        assert!(!source_prefix(&many_closings).1);
        let deep = "<div>".repeat(MAX_CHALLENGE_SOURCE_TAGS);
        assert!(!source_prefix(&deep).1);
        assert_eq!(html_assessment(&deep), ChallengeAssessment::Unreviewed);
        let challenge_first = format!("<input name=captcha>{deep}");
        assert_eq!(html_assessment(&challenge_first), ChallengeAssessment::Detected);
        assert_eq!(
            html_assessment(r#"<p>ordinary</p><b>bold</b>"#),
            ChallengeAssessment::Clear
        );
    }

    #[test]
    fn challenge_budget_respects_quotes_comments_and_raw_text() {
        let markup = "<b>".repeat(MAX_CHALLENGE_FORMATTING_STARTS + 1);
        for body in [
            format!(r#"<div data-text="{markup}"></div>"#),
            format!("<!--{markup}--><div>ordinary</div>"),
            format!("<script>const markup = '{markup}';</script>"),
            format!("<style>/* {markup} */</style>"),
        ] {
            assert!(source_prefix(&body).1);
            assert_eq!(html_assessment(&body), ChallengeAssessment::Clear);
        }
    }

    #[test]
    fn challenge_budget_precedes_stylesheet_ancestor_scans() {
        let body = format!(
            "<template>{}{}{}</template>",
            "<div>".repeat(8190),
            "<style></style>".repeat(8190),
            "</div>".repeat(8190),
        );
        assert_eq!(html_assessment(&body), ChallengeAssessment::Unreviewed);
    }

    #[test]
    fn challenge_uncertainty_withholds_consumer_evidence() {
        for body in [
            br#"<input name="captcha" style="display:none;all:initial">"#.as_slice(),
            br#"<input name="captcha" style="display:&#160;none">"#.as_slice(),
            br#"<div><template shadowrootmode="open"></template><input name="captcha"></div>"#.as_slice(),
        ] {
            let result = crate::checkin::parse_response(body, Some("text/html"));
            assert_eq!(result["raw_evidence"]["raw_withheld_reason"], "response_safety_unreviewed");
            assert!(result["raw_evidence"]["data"].is_null());
        }
        let body = b"<!--><html><input name=captcha><!--tail-->";
        let evidence = crate::drive::Evidence::new(body, Some("application/pdf"), "fixture");
        assert!(evidence.raw_withheld);
        assert_eq!(evidence.raw_withheld_reason.as_deref(), Some("response_safety_unreviewed"));
        assert!(evidence.raw_base64.is_empty());
    }

    #[test]
    fn challenge_assessment_bounds_dom_processing_fail_closed() {
        let depth = MAX_CHALLENGE_DOM_DEPTH + 1;
        let deeply_nested = format!(
            "{}<span></span>{}",
            "<section>".repeat(depth),
            "</section>".repeat(depth)
        );
        assert_eq!(
            html_assessment(&deeply_nested),
            ChallengeAssessment::Unreviewed
        );
        assert_eq!(
            assess_challenge_body(
                vec![b' '; MAX_CHALLENGE_BYTES + 1].as_slice(),
                Some("text/html"),
                true,
            ),
            ChallengeAssessment::Unreviewed
        );
    }

    #[test]
    fn challenge_second_review_refuses_unsupported_native_activity() {
        for body in [
            r#"<dialog><input name="captcha"></dialog>"#,
            r#"<details><input name="captcha"></details>"#,
            r#"<iframe srcdoc="<input name=captcha>"></iframe>"#,
            r#"<input name="captcha" style="display:contents">"#,
            r#"<input name="answer" placeholder="Verification code">"#,
            r#"<label for="answer">验证码</label><input id="answer">"#,
            r#"<input autocomplete="one-time-code">"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Unreviewed, "{body}");
            let output = crate::checkin::parse_response(body.as_bytes(), Some("text/html"));
            assert!(output["raw_evidence"]["data"].is_null());
            assert_eq!(output["raw_evidence"]["raw_withheld_reason"], "response_safety_unreviewed");
        }
        let attributes = (0..40_000).map(|n| format!(" a{n}")).collect::<String>();
        let hostile = format!("<div{attributes}></div>");
        assert_eq!(html_assessment(&hostile), ChallengeAssessment::Unreviewed);
        assert_eq!(html_assessment(&format!("<input name=captcha>{hostile}")), ChallengeAssessment::Detected);
        let iso = b"<meta charset=iso-2022-jp>\x1b$B<div/class=cf-turnstile>\x1b(B";
        assert_eq!(assess_challenge_body(iso, Some("text/html"), true), ChallengeAssessment::Unreviewed);
        assert_eq!(html_assessment("<meta charset=utf-8><input name=captcha>"), ChallengeAssessment::Detected);
        assert_eq!(assess_challenge_body(b"<p>ordinary</p>", Some(r#"text/html; charset="utf\-8"; charset=utf-8"#), true), ChallengeAssessment::Clear);
        for mime in ["application/pdf", "application/vnd.github.raw+json"] {
            let body = b"<!DOCTYPEhtml><html><input name=captcha>";
            assert_eq!(assess_challenge_body(body, Some(mime), true), ChallengeAssessment::Unreviewed);
            assert!(crate::drive::Evidence::new(body, Some(mime), "fixture").raw_withheld);
        }
    }

    #[test]
    fn challenge_third_review_keeps_uncertainty_without_false_latches() {
        for body in [
            r#"<iframe src="/captcha" srcdoc="<p>ordinary</p>"></iframe>"#,
            r#"<style>button::before{content:'Verify';visibility:visible}</style><button name=captcha style='visibility:hidden!important'></button>"#,
        ] {
            assert_eq!(html_assessment(body), ChallengeAssessment::Unreviewed);
            let out = crate::checkin::parse_response(body.as_bytes(), Some("text/html; charset=utf-8"));
            assert_eq!(out["raw_evidence"]["raw_withheld_reason"], "response_safety_unreviewed");
            assert_eq!(html_assessment(&format!("{body}<input name=captcha>")),
                if body.contains("<style>") { ChallengeAssessment::Unreviewed } else { ChallengeAssessment::Detected });
        }
        let shifted = b"<meta charset=iso-2022-jp>\x1b$B<div/class=cf-turnstile>\x1b(B";
        for mime in [None, Some("text/*"), Some("text/html")] {
            assert_eq!(assess_challenge_body(shifted, mime, true), ChallengeAssessment::Unreviewed);
        }
        let interrupted = format!("\x1b$B<div/class=cf-turnstile>\x1b(B{}<meta charset=iso-2022-jp>", "<a>".repeat(249));
        assert_eq!(assess_challenge_body(interrupted.as_bytes(), None, true), ChallengeAssessment::Unreviewed);
        let attributes = (0..40_000).map(|n| format!(" a{n}")).collect::<String>();
        for opening in [r#"<div a=x" b=">""#, r#"<div a=x= " b=">""#] {
            let body = format!("{opening}{attributes}></div>");
            assert!(!token_work_prefix(&body).1);
            assert_eq!(html_assessment(&body), ChallengeAssessment::Unreviewed);
            let prefix = format!("<input name=captcha>{body}");
            assert_eq!(assess_challenge_body(prefix.as_bytes(), Some("text/html; charset=utf-8"), true), ChallengeAssessment::Detected);
        }
    }

    #[test]
    fn truncated_source_cannot_confirm_a_candidate_it_cannot_see() {
        // A stylesheet beyond the formatting budget can still hide the
        // retained candidate, so the truncated prefix must not confirm it.
        let mut body = String::from("<input name=captcha>");
        body.push_str(&"<a></a>".repeat(2_000));
        body.push_str("<style>input{display:none}</style>");
        assert_eq!(
            assess_challenge_body(body.as_bytes(), Some("text/html; charset=utf-8"), true),
            ChallengeAssessment::Unreviewed
        );
        // A stylesheet beyond the decoded prefix has the same effect.
        assert_eq!(
            assess_challenge_body(
                b"<input name=captcha>\xff<style>input{display:none}</style>",
                Some("text/html; charset=utf-8"),
                true
            ),
            ChallengeAssessment::Unreviewed
        );
        // A charset declaration beyond the decoded prefix governs the whole
        // document, so the apparent control is not established either.
        assert_eq!(
            assess_challenge_body(
                b"<input name=captcha>\xff<meta charset=iso-2022-jp>",
                Some("text/html"),
                true
            ),
            ChallengeAssessment::Unreviewed
        );
        // Without such evidence the retained control is still confirmed.
        assert_eq!(
            assess_challenge_body(b"<input name=captcha>\xff", Some("text/html"), true),
            ChallengeAssessment::Detected
        );
        assert_eq!(
            assess_challenge_body(b"<input name=captcha>", Some("text/html"), true),
            ChallengeAssessment::Detected
        );
    }

    #[test]
    fn template_and_noscript_inertness_is_html_namespace_scoped() {
        let document = Html::parse_document(
            r#"<html><body><template id="html-template"><span id="html-template-child">inactive template</span></template><noscript id="html-noscript">inactive noscript</noscript><svg><template id="svg-template"><foreignObject><span id="svg-template-child">active template</span></foreignObject></template><noscript id="svg-noscript"><foreignObject><span id="svg-noscript-child">active noscript</span></foreignObject></noscript></svg><span id="tail">active tail</span></body></html>"#,
        );
        let all = Selector::parse("*").expect("selector");
        let html_template = element_by_id(&document, &all, "html-template");
        let html_noscript = element_by_id(&document, &all, "html-noscript");
        let svg_template = element_by_id(&document, &all, "svg-template");
        let svg_noscript = element_by_id(&document, &all, "svg-noscript");
        assert!(is_inert_text_element(html_template));
        assert!(is_inert_text_element(html_noscript));
        assert!(!is_inert_text_element(svg_template));
        assert!(!is_inert_text_element(svg_noscript));
        assert!(inert_element(element_by_id(
            &document,
            &all,
            "html-template-child"
        )));
        assert!(!inert_element(element_by_id(
            &document,
            &all,
            "svg-template-child"
        )));

        let body = Selector::parse("body").expect("selector");
        let body = document.select(&body).next().expect("body");
        assert_eq!(
            active_element_text(body),
            "active template active noscript active tail"
        );
    }
}

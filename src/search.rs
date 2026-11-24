//! Unified offline search over everything this binary knows.
//!
//! One index covers the acceptance capabilities with their evidence and
//! blockers, the evidence sections of `docs/STATUS.md`, every documentation
//! page shipped with the binary, and the graduation credit catalog. The
//! command is offline and deterministic: it opens no socket, reads no
//! operator state, and never reaches a service.

use serde::de::value::MapAccessDeserializer;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::LazyLock;

const ACCEPTANCE: &str = include_str!("../acceptance.json");
const CREDITS: &str = include_str!("credits_catalog.json");
const STATUS: &str = include_str!("../docs/STATUS.md");

const DOCS: [(&str, &str); 16] = [
    ("docs/ARCHIVE.md", include_str!("../docs/ARCHIVE.md")),
    (
        "docs/CAS-LOGIN-PROTOCOL.md",
        include_str!("../docs/CAS-LOGIN-PROTOCOL.md"),
    ),
    (
        "docs/CAS-SERVICE-CATALOG.md",
        include_str!("../docs/CAS-SERVICE-CATALOG.md"),
    ),
    ("docs/FENGRUBEI.md", include_str!("../docs/FENGRUBEI.md")),
    ("docs/GATEWAY.md", include_str!("../docs/GATEWAY.md")),
    ("docs/ORGANIZATIONS.md", include_str!("../docs/ORGANIZATIONS.md")),
    ("docs/RECORDINGS.md", include_str!("../docs/RECORDINGS.md")),
    ("docs/REFERENCES.md", include_str!("../docs/REFERENCES.md")),
    ("docs/SPOC.md", include_str!("../docs/SPOC.md")),
    (
        "docs/SSO-LOGIN-PROTOCOL.md",
        include_str!("../docs/SSO-LOGIN-PROTOCOL.md"),
    ),
    (
        "docs/features/index.md",
        include_str!("../docs/features/index.md"),
    ),
    (
        "docs/features/judge.md",
        include_str!("../docs/features/judge.md"),
    ),
    (
        "docs/features/finance.md",
        include_str!("../docs/features/finance.md"),
    ),
    (
        "docs/features/agenda.md",
        include_str!("../docs/features/agenda.md"),
    ),
    (
        "docs/design/graceful-degradation.md",
        include_str!("../docs/design/graceful-degradation.md"),
    ),
    ("docs/index.html", include_str!("../docs/index.html")),
];

const KINDS: [&str; 4] = ["capability", "credit_course", "doc", "status_section"];
const MAX_QUERY: usize = 200;
const MAX_LIMIT: usize = 100;
const DEFAULT_LIMIT: usize = 20;
const SNIPPET: usize = 220;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    query: String,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

struct Entry {
    kind: &'static str,
    id: String,
    title: String,
    summary: String,
    body: String,
    source: String,
    fields: Vec<(String, String)>,
    status: Option<String>,
}

fn invalid(message: &str) -> Value {
    json!({"error": "invalid_input", "message": message})
}

/// A map-only admission for the typed input. The visitor never accepts a
/// positional sequence, so a JSON array root is refused before any field is
/// read, and the typed fields still refuse duplicate and unknown members.
struct ObjectOnly;

impl<'de> DeserializeSeed<'de> for ObjectOnly {
    type Value = Input;

    fn deserialize<D>(self, deserializer: D) -> Result<Input, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ObjectOnlyVisitor)
    }
}

struct ObjectOnlyVisitor;

impl<'de> Visitor<'de> for ObjectOnlyVisitor {
    type Value = Input;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("one search JSON object")
    }

    fn visit_map<M>(self, map: M) -> Result<Input, M::Error>
    where
        M: MapAccess<'de>,
    {
        Input::deserialize(MapAccessDeserializer::new(map))
    }
}

/// Render one JSON value as searchable text. Strings stay verbatim, arrays
/// become one line per element, and objects keep every field as compact
/// JSON so no evidence element is dropped.
fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(value_text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

static INDEX: LazyLock<Vec<Entry>> = LazyLock::new(build_index);

fn build_index() -> Vec<Entry> {
    let mut entries = Vec::new();
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(ACCEPTANCE) {
        if let Some(Value::Array(capabilities)) = map.get("capabilities") {
            for capability in capabilities {
                let Some(id) = capability.get("id").and_then(Value::as_str) else {
                    continue;
                };
                let title = capability
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let status = capability
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let mut fields = Vec::new();
                let mut body = String::new();
                if let Some(status) = status.as_deref() {
                    fields.push(("status".to_owned(), status.to_owned()));
                    body.push_str(status);
                    body.push('\n');
                }
                if let Some(Value::Array(sources)) = capability.get("sources") {
                    for source in sources {
                        if let Some(source) = source.as_str() {
                            fields.push(("source".to_owned(), source.to_owned()));
                            body.push_str(source);
                            body.push('\n');
                        }
                    }
                }
                if let Some(Value::Object(evidence)) = capability.get("evidence") {
                    for (key, value) in evidence {
                        let text = value_text(value);
                        if text.is_empty() {
                            continue;
                        }
                        fields.push((key.clone(), text.clone()));
                        body.push_str(&text);
                        body.push('\n');
                    }
                }
                // Every remaining top-level field of the capability is indexed
                // as it is written: the blocker, the acceptance criterion, the
                // remaining work, the linked issue, and any dated observation.
                if let Value::Object(fields_map) = capability {
                    for (key, value) in fields_map {
                        match key.as_str() {
                            "id" | "title" | "status" | "sources" | "evidence" => continue,
                            _ => {}
                        }
                        let text = value_text(value);
                        if text.is_empty() {
                            continue;
                        }
                        fields.push((key.clone(), text.clone()));
                        body.push_str(&text);
                        body.push('\n');
                    }
                }
                let summary = capability
                    .get("acceptance")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                entries.push(Entry {
                    kind: "capability",
                    id: id.to_owned(),
                    title,
                    summary,
                    body,
                    source: format!("acceptance.json#{id}"),
                    fields,
                    status,
                });
            }
        }
    }
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(CREDITS) {
        if let Some(Value::Array(courses)) = map.get("courses") {
            for course in courses {
                let Some(name) = course.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let mut fields = Vec::new();
                let mut body = String::from(name);
                for key in ["credit", "grade", "term"] {
                    if let Some(value) = course.get(key) {
                        let text = value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string());
                        fields.push((key.to_owned(), text.clone()));
                        body.push('\n');
                        body.push_str(&text);
                    }
                }
                if let Some(Value::Array(majors)) = course.get("majors") {
                    for major in majors {
                        if let Some(major) = major.as_str() {
                            fields.push(("major".to_owned(), major.to_owned()));
                            body.push('\n');
                            body.push_str(major);
                        }
                    }
                }
                entries.push(Entry {
                    kind: "credit_course",
                    id: name.to_owned(),
                    title: name.to_owned(),
                    summary: format!("credit catalog course {name}"),
                    body,
                    source: "credits_catalog.json".to_owned(),
                    fields,
                    status: None,
                });
            }
        }
    }
    for (path, text) in DOCS {
        let (title, text) = if path.ends_with(".html") {
            (html_title(text), html_text(text))
        } else {
            (document_title(text), text.to_owned())
        };
        entries.push(Entry {
            kind: "doc",
            id: path.to_owned(),
            title: title.unwrap_or_else(|| path.to_owned()),
            summary: first_paragraph(&text),
            body: text,
            source: path.to_owned(),
            fields: vec![("path".to_owned(), path.to_owned())],
            status: None,
        });
    }
    for (title, body) in status_sections(STATUS) {
        entries.push(Entry {
            kind: "status_section",
            id: format!("docs/STATUS.md#{title}"),
            title: title.clone(),
            summary: first_paragraph(&body),
            body,
            source: "docs/STATUS.md".to_owned(),
            fields: vec![("section".to_owned(), title)],
            status: None,
        });
    }
    entries
}

fn document_title(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(title) = trimmed.strip_prefix("# ") {
            return Some(title.trim().to_owned());
        }
    }
    None
}

/// Read the `<title>` of one HTML page.
fn html_title(markup: &str) -> Option<String> {
    let start = markup.to_ascii_lowercase().find("<title>")? + "<title>".len();
    let end = markup[start..].to_ascii_lowercase().find("</title>")? + start;
    let title = markup[start..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(decode_entities(title))
    }
}

/// Extract the readable text of one HTML page. Script and style content is
/// dropped, block elements become separate lines, and the common entities
/// are decoded, so the page is searchable and its snippets stay readable.
fn html_text(markup: &str) -> String {
    let mut out = String::with_capacity(markup.len() / 2);
    let mut index = 0usize;
    while index < markup.len() {
        let Some(relative) = markup[index..].find('<') else {
            out.push_str(&markup[index..]);
            break;
        };
        let tag_start = index + relative;
        out.push_str(&markup[index..tag_start]);
        let Some(relative_end) = markup[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + relative_end;
        let tag = &markup[tag_start + 1..tag_end];
        let closing = tag.starts_with('/');
        let name = tag
            .trim_start_matches('/')
            .split(|character: char| character.is_whitespace() || character == '/')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        index = tag_end + 1;
        if matches!(name.as_str(), "script" | "style") && !closing {
            let close = format!("</{name}");
            match markup[index..].to_ascii_lowercase().find(&close) {
                Some(found) => index += found,
                None => break,
            }
            continue;
        }
        if !closing
            && matches!(
                name.as_str(),
                "p" | "div"
                    | "section"
                    | "article"
                    | "li"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "h5"
                    | "h6"
                    | "br"
                    | "tr"
                    | "td"
                    | "title"
            )
        {
            out.push('\n');
        }
    }
    collapse_whitespace(&decode_entities(&out))
}

fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    while let Some(relative) = text[index..].find('&') {
        let start = index + relative;
        out.push_str(&text[index..start]);
        let tail = &text[start..];
        let decoded = tail
            .find(';')
            .filter(|end| *end <= 10)
            .and_then(|end| match &tail[1..end] {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" | "#39" => Some('\''),
                "nbsp" => Some(' '),
                "mdash" => Some('\u{2014}'),
                "ndash" => Some('\u{2013}'),
                "hellip" => Some('\u{2026}'),
                "middot" => Some('\u{00b7}'),
                _ => None,
            });
        match decoded {
            Some(character) => {
                out.push(character);
                index = start + tail.find(';').unwrap_or(0) + 1;
            }
            None => {
                out.push('&');
                index = start + 1;
            }
        }
    }
    out.push_str(&text[index..]);
    out
}

fn collapse_whitespace(text: &str) -> String {
    let mut lines = Vec::new();
    for line in text.lines() {
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !line.is_empty() {
            lines.push(line);
        }
    }
    lines.join("\n")
}

fn first_paragraph(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if out.is_empty() {
                continue;
            }
            break;
        }
        if trimmed.starts_with('#') || trimmed.starts_with("---") {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(trimmed);
    }
    out
}

fn status_sections(text: &str) -> Vec<(String, String)> {
    let mut sections = Vec::new();
    let mut current: Option<(String, String)> = None;
    let mut preamble = String::new();
    for line in text.lines() {
        let heading = line
            .strip_prefix("## ")
            .or_else(|| line.strip_prefix("### "));
        if let Some(title) = heading {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some((title.trim().to_owned(), String::new()));
            continue;
        }
        match current.as_mut() {
            Some((_, body)) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {
                preamble.push_str(line);
                preamble.push('\n');
            }
        }
    }
    if let Some(section) = current {
        sections.push(section);
    }
    if !preamble.trim().is_empty() {
        sections.insert(0, ("overview".to_owned(), preamble));
    }
    sections
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.to_lowercase().matches(&needle.to_lowercase()).count()
}

fn score_entry(entry: &Entry, terms: &[String]) -> Option<(usize, String)> {
    let mut score = 0usize;
    let mut snippet = String::new();
    for term in terms {
        let mut matched = false;
        if entry.id.to_lowercase().contains(term) {
            score += 8;
            matched = true;
            if snippet.is_empty() {
                snippet = entry.id.clone();
            }
        }
        if entry.title.to_lowercase().contains(term) {
            score += 6;
            matched = true;
            if snippet.is_empty() {
                snippet = entry.title.clone();
            }
        }
        if entry.summary.to_lowercase().contains(term) {
            score += 4;
            matched = true;
            if snippet.is_empty() {
                snippet = entry.summary.clone();
            }
        }
        let hits = occurrences(&entry.body, term);
        if hits > 0 {
            score += 2 + hits.min(3);
            matched = true;
            if snippet.is_empty() {
                snippet = snippet_around(&entry.body, term);
            }
        }
        if !matched {
            return None;
        }
    }
    Some((score, snippet))
}

fn snippet_around(body: &str, term: &str) -> String {
    let lowered = body.to_lowercase();
    let position = lowered.find(term).unwrap_or(0);
    let start = body[..position]
        .char_indices()
        .rev()
        .take(SNIPPET)
        .last()
        .map(|(index, _)| index)
        .unwrap_or(0);
    let end = body[start..]
        .char_indices()
        .take(SNIPPET)
        .last()
        .map(|(index, character)| start + index + character.len_utf8())
        .unwrap_or(body.len());
    body[start..end].replace('\n', " ").trim().to_owned()
}

/// Search the whole offline index. The input is one JSON object with a
/// required `query`, optional `kinds` and `status` filters, and optional
/// `limit` and `cursor`.
pub fn search(input: &str) -> Value {
    // One JSON object is the only accepted root: a positional array or any
    // other value is refused before the typed fields are read, and a
    // duplicate member stays a duplicate member.
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let parsed: Input = match ObjectOnly.deserialize(&mut deserializer) {
        Ok(parsed) => parsed,
        Err(_) => return invalid("input must be one search JSON object"),
    };
    if deserializer.end().is_err() {
        return invalid("input must be one search JSON object");
    }
    let query = parsed.query.trim();
    if query.is_empty() || query.chars().count() > MAX_QUERY {
        return invalid("query must be 1 to 200 characters");
    }
    let mut kinds = BTreeSet::new();
    for kind in &parsed.kinds {
        if !KINDS.contains(&kind.as_str()) {
            return invalid("kind is not one of capability, credit_course, doc, status_section");
        }
        kinds.insert(kind.clone());
    }
    if let Some(status) = parsed.status.as_deref() {
        if status.is_empty() || status.chars().count() > 64 {
            return invalid("status must be 1 to 64 characters");
        }
    }
    let limit = parsed.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return invalid("limit must be 1 to 100");
    }
    let offset = match parsed.cursor.as_deref() {
        None | Some("") => 0usize,
        Some(cursor) => match cursor
            .strip_prefix("offset:")
            .and_then(|value| value.parse().ok())
        {
            Some(offset) => offset,
            None => return invalid("cursor is not a known pagination cursor"),
        },
    };
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|term| term.to_lowercase())
        .filter(|term| !term.is_empty())
        .collect();
    if terms.is_empty() {
        return invalid("query must be 1 to 200 characters");
    }
    let mut matched: Vec<(usize, &Entry, String)> = Vec::new();
    for entry in INDEX.iter() {
        if !kinds.is_empty() && !kinds.contains(entry.kind) {
            continue;
        }
        if let Some(status) = parsed.status.as_deref() {
            if entry.kind != "capability" {
                continue;
            }
            if entry.status.as_deref() != Some(status) {
                continue;
            }
        }
        if let Some((score, snippet)) = score_entry(entry, &terms) {
            matched.push((score, entry, snippet));
        }
    }
    matched.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.kind.cmp(right.1.kind))
            .then_with(|| left.1.id.cmp(&right.1.id))
    });
    let total = matched.len();
    let results: Vec<Value> = matched
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(score, entry, snippet)| {
            let mut fields = serde_json::Map::new();
            for (key, value) in &entry.fields {
                fields.insert(key.clone(), json!(value));
            }
            json!({
                "kind": entry.kind,
                "id": entry.id,
                "title": entry.title,
                "summary": snippet.chars().take(SNIPPET).collect::<String>(),
                "source": entry.source,
                "score": score,
                "fields": Value::Object(fields)
            })
        })
        .collect();
    let returned = results.len();
    let next_offset = offset + returned;
    json!({
        "schema_version": 1,
        "type": "search",
        "query": query,
        "kinds": if kinds.is_empty() { json!(KINDS) } else { json!(kinds) },
        "status": parsed.status,
        "total": total,
        "returned": returned,
        "results": results,
        "next_cursor": if next_offset < total { json!(format!("offset:{next_offset}")) } else { Value::Null },
        "coverage": "embedded_capabilities_evidence_documents_and_credit_catalog",
        "network_performed": false,
        "read_only": true
    })
}

pub fn schema() -> Value {
    json!({
        "stdin": "one search JSON object; this command performs no network request and reads no operator state",
        "query": "required text of 1 to 200 characters; whitespace separates terms and every term must match",
        "kinds": "optional filter over capability, credit_course, doc and status_section; an empty list searches every kind",
        "status": "optional filter that keeps only capability entries with that acceptance status",
        "limit": "optional result count, 1 to 100, default 20",
        "cursor": "optional pagination cursor returned by the previous call",
        "coverage": "the acceptance capabilities with their evidence and blockers, every shipped documentation page, the status evidence sections and the graduation credit catalog",
        "failure": "an unknown kind, an empty query or an unknown cursor is invalid_input and returns no results"
    })
}

#[cfg(test)]
mod tests {
    use super::search;
    use serde_json::json;

    fn kind_counts() -> std::collections::BTreeMap<&'static str, usize> {
        super::INDEX
            .iter()
            .fold(std::collections::BTreeMap::new(), |mut counts, entry| {
                *counts.entry(entry.kind).or_insert(0) += 1;
                counts
            })
    }

    #[test]
    fn every_kind_is_indexed_and_filtered() {
        let all = search(&json!({"query": "buaa"}).to_string());
        assert!(all["total"].as_u64().unwrap() > 0);
        let docs = search(&json!({"query": "buaa", "kinds": ["doc"]}).to_string());
        assert_eq!(docs["kinds"], json!(["doc"]));
        for result in docs["results"].as_array().unwrap() {
            assert_eq!(result["kind"], "doc");
        }
    }

    #[test]
    fn capability_evidence_is_searchable_and_status_filters() {
        let output = search(&json!({"query": "judge"}).to_string());
        let kinds: Vec<&str> = output["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|result| result["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"capability"));
        let live = search(
            &json!({"query": "judge", "kinds": ["capability"], "status": "partial-live-verified"})
                .to_string(),
        );
        assert!(live["total"].as_u64().unwrap() >= 1);
        for result in live["results"].as_array().unwrap() {
            assert_eq!(result["fields"]["status"], json!("partial-live-verified"));
        }
        let by_status = search(&json!({"query": "partial-live-verified"}).to_string());
        assert!(
            by_status["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|result| result["kind"] == "capability"),
            "the acceptance status is not searchable"
        );
    }

    #[test]
    fn unknown_kind_and_cursor_are_refused() {
        assert_eq!(
            search(&json!({"query": "x", "kinds": ["nope"]}).to_string())["error"],
            "invalid_input"
        );
        assert_eq!(
            search(&json!({"query": "x", "cursor": "nope"}).to_string())["error"],
            "invalid_input"
        );
        assert_eq!(
            search(&json!({"query": "  "}).to_string())["error"],
            "invalid_input"
        );
    }

    #[test]
    fn pagination_walks_the_same_result_set() {
        let first = search(&json!({"query": "buaa", "limit": 2}).to_string());
        assert_eq!(first["returned"], 2);
        let cursor = first["next_cursor"].as_str().unwrap().to_owned();
        let second = search(&json!({"query": "buaa", "limit": 2, "cursor": cursor}).to_string());
        assert_eq!(second["total"], first["total"]);
        assert_ne!(second["results"], first["results"]);
    }

    #[test]
    fn the_index_covers_every_document_and_status_section() {
        let counts = kind_counts();
        assert_eq!(counts.get("doc"), Some(&16));
        assert!(counts.get("status_section").copied().unwrap_or(0) >= 140);
        assert!(counts.get("capability").copied().unwrap_or(0) >= 50);
        assert!(counts.get("credit_course").copied().unwrap_or(0) >= 100);
        let docs = search(&json!({"query": "CAS-LOGIN-PROTOCOL"}).to_string());
        assert!(
            docs["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|result| result["id"] == "docs/CAS-LOGIN-PROTOCOL.md")
        );
        let all = search(&json!({"query": "buaa", "kinds": ["doc"], "limit": 100}).to_string());
        assert_eq!(all["total"], 16);
        for page in ["docs/index.html", "docs/design/graceful-degradation.md"] {
            assert!(
                all["results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|result| result["id"] == page),
                "missing page {page}"
            );
        }
    }

    #[test]
    fn only_one_json_object_is_accepted() {
        for root in [
            r#"["buaa",[],null,1,null]"#,
            "[]",
            "\"buaa\"",
            "null",
            "42",
            "{\"query\":\"buaa\"} trailing",
            "{\"query\":\"buaa\"} {\"query\":\"buaa\"}",
        ] {
            assert_eq!(
                search(root)["error"],
                "invalid_input",
                "accepted {root}"
            );
        }
        // A duplicate member stays a duplicate member: the last one never
        // silently replaces the first one.
        for root in [
            "{\"query\":\"\",\"query\":\"buaa\"}",
            "{\"query\":\"buaa\",\"query\":\"buaa\"}",
            "{\"query\":\"buaa\",\"limit\":1,\"limit\":2}",
        ] {
            assert_eq!(
                search(root)["error"],
                "invalid_input",
                "accepted {root}"
            );
        }
    }

    #[test]
    fn capability_blockers_and_object_evidence_are_searchable() {
        let blocker = search(&json!({"query": "Real service allocation"}).to_string());
        let crater = blocker["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["id"] == "crater")
            .expect("crater capability");
        assert!(
            crater["fields"]["blocker"]
                .as_str()
                .unwrap()
                .contains("Real service allocation"),
            "top-level blocker is not indexed"
        );
        let evidence = search(
            &json!({"query": "announcements college-source aviation root --refresh"}).to_string(),
        );
        let announcements = evidence["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["id"] == "announcements")
            .expect("announcements capability");
        assert!(
            announcements["fields"]["live_verification"]
                .as_str()
                .unwrap()
                .contains("college-source aviation root"),
            "object evidence elements are dropped"
        );
    }
}

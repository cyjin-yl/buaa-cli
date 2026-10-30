//! Authoritative organization directory parsing over one fixed official source.
use crate::announcements::refuse_unsafe_listing;
use crate::html::{
    css_trim, element_text, inert_element, split_declarations, split_important, strip_css_comments,
};
use crate::net::{
    ArchiveClient, CacheMode, CookieAdmission, Error, ORGANIZATIONS_URL, Response,
    sensitive_text_marker,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use scraper::{ElementRef, Html, Node, Selector};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::Url;

const MAX_HTML: usize = 2 * 1024 * 1024;
const MAX_GROUPS: usize = 64;
const MAX_ENTRIES: usize = 512;
const MAX_TEXT: usize = 512;
const MAX_HREF: usize = 4096;

#[derive(Debug, Serialize)]
pub struct Organization {
    pub source_order: usize,
    pub category: String,
    pub name: String,
    pub listed_href: Option<String>,
    pub resolved_http_url: Option<String>,
    pub link_kind: &'static str,
    pub hidden_in_source: bool,
}

#[derive(Debug, Serialize)]
pub struct DirectoryDocument {
    pub title: String,
    pub categories: Vec<String>,
    pub entries: Vec<Organization>,
}

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "official organization directory could not be interpreted safely",
    )
}

/// Parse the official directory document. This is public for offline evidence
/// validation and library consumers; it performs no network or cache access.
pub fn parse_html(bytes: &[u8]) -> Result<DirectoryDocument, Error> {
    parse_document(&admitted_html(bytes)?)
}

fn admitted_html(bytes: &[u8]) -> Result<Html, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let input = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(input);
    let bases = Selector::parse("base[href]").map_err(|_| unavailable())?;
    if document.select(&bases).any(|base| !inert_element(base)) {
        return Err(unavailable());
    }
    Ok(document)
}

/// Organization markers use the shared CSS lexer, but resolve their own
/// authority policy. Unresolved style is non-attributing, not measured native
/// browser visibility.
#[derive(Default)]
struct NodeMarkers {
    hides_subtree: bool,
    visibility: Option<bool>,
    unresolved: bool,
}

fn marker_style(style: &str) -> NodeMarkers {
    let mut markers = NodeMarkers::default();
    let Some(style) = strip_css_comments(style) else {
        markers.unresolved = true;
        return markers;
    };
    let Ok(declarations) = split_declarations(&style) else {
        markers.unresolved = true;
        return markers;
    };
    let mut display: Option<(bool, bool)> = None;
    let mut visibility: Option<(bool, bool)> = None;
    let mut content_visibility: Option<(bool, bool)> = None;
    for (property, value) in declarations {
        if property.eq_ignore_ascii_case("all")
            || property.contains(['\\', '"', '\''])
            || property.contains("/*")
        {
            markers.unresolved = true;
            continue;
        }
        let target = if property.eq_ignore_ascii_case("display") {
            &mut display
        } else if property.eq_ignore_ascii_case("visibility") {
            &mut visibility
        } else if property.eq_ignore_ascii_case("content-visibility") {
            &mut content_visibility
        } else {
            continue;
        };
        let (body, important) = split_important(css_trim(value));
        let body = css_trim(body).to_ascii_lowercase();
        if body.contains(['(', '"', '\'', '\\'])
            || matches!(
                body.as_str(),
                "inherit" | "initial" | "unset" | "revert" | "revert-layer"
            )
        {
            markers.unresolved = true;
            continue;
        }
        let hide = if property.eq_ignore_ascii_case("display") {
            match body.as_str() {
                "none" => Some(true),
                "inline" | "block" | "inline-block" | "flow-root" | "list-item" | "table"
                | "flex" | "grid" | "run-in" | "inline-table" | "table-row" | "table-cell"
                | "table-caption" | "table-column" | "table-column-group" | "table-row-group"
                | "table-footer-group" | "inline-flex" | "inline-grid" => Some(false),
                _ => None,
            }
        } else if property.eq_ignore_ascii_case("visibility") {
            match body.as_str() {
                "hidden" | "collapse" => Some(true),
                "visible" => Some(false),
                _ => None,
            }
        } else {
            match body.as_str() {
                "hidden" => Some(true),
                "visible" => Some(false),
                _ => {
                    markers.unresolved = true;
                    None
                }
            }
        };
        // Bare invalid values do not override any valid earlier declaration.
        let Some(hide) = hide else { continue };
        let replaced = match target {
            Some((_, previous_important)) => important || !*previous_important,
            None => true,
        };
        if replaced {
            *target = Some((hide, important));
        }
    }
    markers.hides_subtree = matches!(display, Some((true, _)))
        || matches!(content_visibility, Some((true, _)));
    markers.visibility = visibility.map(|(hide, _)| hide);
    markers
}

fn hidden_in_source(element: ElementRef<'_>) -> bool {
    let mut visibility_decided = false;
    for node in std::iter::once(element)
        .chain(element.ancestors().filter_map(ElementRef::wrap))
    {
        let value = node.value();
        if value.attr("hidden").is_some()
            || value.attr("class").is_some_and(|classes| {
                classes.split_ascii_whitespace().any(|class| class == "xbt")
            })
        {
            return true;
        }
        let markers = marker_style(value.attr("style").unwrap_or_default());
        if markers.unresolved || markers.hides_subtree {
            return true;
        }
        if !visibility_decided {
            match markers.visibility {
                Some(true) => return true,
                Some(false) => visibility_decided = true,
                None => {}
            }
        }
    }
    false
}

/// Decodes only bounded `&#N;`/`&#xN;` numeric references; malformed or named
/// entities pass through literally. Attribute values dropped by HTML parsing
/// (duplicate names) stay reachable to the raw scan through this decode.
fn decode_numeric_entities(source: &str) -> Option<String> {
    if !source.contains("&#") {
        return None;
    }
    let mut decoded = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("&#") {
        decoded.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let (digits, hex) = match after.strip_prefix(['x', 'X']) {
            Some(tail) => (tail, true),
            None => (after, false),
        };
        let end = digits
            .find(|c: char| if hex { !c.is_ascii_hexdigit() } else { !c.is_ascii_digit() })
            .unwrap_or(digits.len());
        if end == 0 || end == digits.len() || digits.as_bytes()[end] != b';' {
            decoded.push_str("&#");
            rest = after;
            continue;
        }
        match u32::from_str_radix(&digits[..end], if hex { 16 } else { 10 })
            .ok()
            .and_then(char::from_u32)
        {
            Some(c) => decoded.push(c),
            // `after` retains a leading "x"/"X" only when `hex` is set, so the
            // full literal reference ends at `start + 2 + hex + end + 1`.
            None => decoded.push_str(&rest[start..start + 2 + (hex as usize) + end + 1]),
        }
        rest = &digits[end + 1..];
    }
    decoded.push_str(rest);
    Some(decoded)
}

/// Attribute-only admission is not enough for original-byte export: inert
/// script/style/template payloads, comments, text and DOM-discarded raw
/// attributes still occur in the source. Known vocabulary markers are checked
/// literally, after numeric-entity decoding, and per identifier token.
fn raw_export_safe(bytes: &[u8], document: &Html) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else { return false };
    let source_safe = !sensitive_text_marker(source)
        && decode_numeric_entities(source).is_none_or(|decoded| !sensitive_text_marker(&decoded));
    source_safe && !document.tree.root().descendants().any(|node| match node.value() {
        Node::Text(text) => sensitive_text_marker(&text.text),
        Node::Comment(comment) => sensitive_text_marker(&comment.comment),
        Node::Element(element) => element.attrs.iter().any(|(name, value)| {
            sensitive_text_marker(name.local.as_ref()) || sensitive_text_marker(value.as_ref())
        }),
        Node::Doctype(doctype) => {
            sensitive_text_marker(&doctype.name)
                || sensitive_text_marker(&doctype.public_id)
                || sensitive_text_marker(&doctype.system_id)
        }
        Node::ProcessingInstruction(pi) => {
            sensitive_text_marker(&pi.target) || sensitive_text_marker(&pi.data)
        }
        Node::Document | Node::Fragment => false,
    })
}

fn parse_document(document: &Html) -> Result<DirectoryDocument, Error> {
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let box_selector = Selector::parse(".kyjg-box").map_err(|_| unavailable())?;
    let category_selector = Selector::parse(".kyjg-tit h3").map_err(|_| unavailable())?;
    let entry_selector = Selector::parse(".kyjg-bd a").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .find(|element| !inert_element(*element))
        .map(element_text)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(unavailable)?;
    let base = Url::parse(ORGANIZATIONS_URL).map_err(|_| unavailable())?;
    let mut categories = Vec::new();
    let mut seen_categories = BTreeSet::new();
    let mut entries = Vec::new();
    for group in document.select(&box_selector) {
        if inert_element(group) {
            continue;
        }
        let category = group
            .select(&category_selector)
            .find(|element| !inert_element(*element))
            .map(element_text)
            .filter(|value| {
                !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
            })
            .ok_or_else(unavailable)?;
        if !seen_categories.insert(category.clone()) || categories.len() == MAX_GROUPS {
            return Err(unavailable());
        }
        categories.push(category.clone());
        let group_entry_start = entries.len();
        for element in group.select(&entry_selector) {
            if inert_element(element) {
                continue;
            }
            if entries.len() == MAX_ENTRIES {
                return Err(unavailable());
            }
            let name = element_text(element);
            if name.is_empty()
                || name.len() > MAX_TEXT
                || name.chars().any(|character| character.is_control())
            {
                return Err(unavailable());
            }
            let listed_href = element.value().attr("href").map(str::to_owned);
            if listed_href.as_ref().is_some_and(|value| {
                value.trim().is_empty()
                    || value.len() > MAX_HREF
                    || value.chars().any(|character| character.is_control())
            }) {
                return Err(unavailable());
            }
            let (resolved_http_url, link_kind) = match listed_href.as_deref() {
                None => (None, "missing"),
                Some(value) => match base.join(value.trim()) {
                    Ok(url)
                        if matches!(url.scheme(), "http" | "https")
                            && url.host_str().is_some()
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.fragment().is_none() =>
                    {
                        let kind = if url.scheme() == "https" {
                            "https"
                        } else {
                            "http"
                        };
                        (Some(url.to_string()), kind)
                    }
                    Ok(_) => (None, "non_http"),
                    Err(_) => (None, "invalid"),
                },
            };
            entries.push(Organization {
                source_order: entries.len() + 1,
                category: category.clone(),
                name,
                listed_href,
                resolved_http_url,
                link_kind,
                hidden_in_source: hidden_in_source(element),
            });
        }
        if entries.len() == group_entry_start {
            return Err(unavailable());
        }
    }
    if categories.is_empty() || entries.is_empty() {
        return Err(unavailable());
    }
    Ok(DirectoryDocument {
        title,
        categories,
        entries,
    })
}

fn retrieval(response: &Response) -> Value {
    json!({
        "source_url": response.url,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "cache_status": response.cache_status,
        "revalidated_at_unix_ms": response.revalidated_at_unix_ms,
        "revalidation_status": response.revalidation_status,
        "response_body_sha256": response.sha256,
        "response_body_byte_length": response.body.len(),
        "http": {"status": response.status, "headers": response.headers}
    })
}

fn normalize(response: &Response, admission: CookieAdmission) -> Result<Value, Error> {
    if response.url != ORGANIZATIONS_URL
        || response.status != 200
        || !response.headers.get("content-type").is_some_and(|value| {
            value.split(';').next().unwrap_or_default()
                .trim_matches([' ', '\t']).eq_ignore_ascii_case("text/html")
        })
    {
        return Err(unavailable());
    }
    let document = admitted_html(&response.body)?;
    refuse_unsafe_listing(response, &document)?;
    if admission == CookieAdmission::Unknown {
        // A legacy body might contain opaque private strings even in valid
        // directory fields: no source-derived projection is safe to emit.
        return Ok(directory_fallback(response, None,
            "organization_directory_provenance_unknown"));
    }
    // Cookie-freeness is only a transport fact. Both structured fields and
    // original-byte fallback must pass the complete source/DOM privacy gate.
    // A known sensitive document is outer Err: ArchiveClient never saves it.
    if !raw_export_safe(&response.body, &document) {
        return Err(unavailable());
    }
    match normalize_document(response, &document) {
        Ok(value) => Ok(value),
        Err(_) => Ok(directory_fallback(response, Some(STANDARD.encode(&response.body)),
            "organization_directory_selector_contract")),
    }
}

fn normalize_document(response: &Response, document: &Html) -> Result<Value, Error> {
    let parsed = parse_document(document)?;
    let entry_count = parsed.entries.len();
    let category_count = parsed.categories.len();
    Ok(json!({
        "schema_version": 1,
        "type": "organization_directory",
        "result": "directory_snapshot",
        "authority": {
            "publisher": "北京航空航天大学",
            "directory_label": "教学科研机构",
            "source_url": ORGANIZATIONS_URL
        },
        "document_title": parsed.title,
        "categories": parsed.categories,
        "entries": parsed.entries,
        "completeness": {
            "scope": "entries_in_captured_official_directory_document",
            "includes_hidden_source_entries": true,
            "entry_count": entry_count,
            "category_count": category_count,
            "university_wide_beyond_this_document": false
        },
        "retrieval": retrieval(response)
    }))
}

fn directory_fallback(response: &Response, raw: Option<String>, reason: &str) -> Value {
    let withheld = raw.is_none();
    // Retained header values may themselves be opaque private strings. A
    // metadata-only legacy result must not echo ETag or Content-Type parameters.
    let mut provenance = retrieval(response);
    provenance["http"] = json!({"status": response.status, "headers": {}, "headers_withheld": true});
    json!({
        "schema_version": 1,
        "type": "organization_directory",
        "result": "fallback",
        "authority": {
            "publisher": "北京航空航天大学",
            "directory_label": "教学科研机构",
            "source_url": ORGANIZATIONS_URL
        },
        "entries": [],
        "raw_html": raw,
        "raw_withheld": withheld,
        "raw_withheld_reason": if withheld { Some("cookie_provenance_unavailable") } else { None },
        "raw_html_sha256": response.sha256,
        "content_type": "text/html",
        "body_byte_length": response.body.len(),
        "fallback_reason": reason,
        "retrieval": provenance
    })
}

pub fn list(mode: CacheMode) -> Result<Value, Error> {
    list_with_client(&ArchiveClient::open_organizations(mode)?)
}

/// Callers supply an isolated ArchiveClient for offline fixture proof; this
/// seam never changes the fixed official URL or the client's governor/lease.
pub(crate) fn list_with_client(client: &ArchiveClient) -> Result<Value, Error> {
    let url = Url::parse(ORGANIZATIONS_URL).map_err(|_| unavailable())?;
    client.get_with_admission(&url, false, normalize)
}

#[cfg(all(feature = "directory-admission-proof", not(feature = "directory-admission-proof-candidate")))]
pub(crate) fn normalize_for_proof(response: &Response) -> Result<Value, Error> {
    normalize(response, CookieAdmission::Unknown)
}

#[cfg(feature = "directory-admission-proof-candidate")]
pub(crate) fn normalize_for_proof(
    response: &Response,
    admission: crate::net::CookieAdmission,
) -> Result<Value, Error> {
    normalize(response, admission)
}

pub fn schema() -> Value {
    let mut schema = json!({"list": {
        "input": {"type":"null","description":"No stdin. Default is private cache only; --online and --refresh are explicit options."},
        "output": {
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "type":"object","additionalProperties":false,
            "required":["schema_version","type","result","authority","document_title","categories","entries","completeness","retrieval"],
            "properties": {
                "schema_version":{"const":1},"type":{"const":"organization_directory"},"result":{"const":"directory_snapshot"},
                "authority":{"type":"object","additionalProperties":false,"required":["publisher","directory_label","source_url"],"properties":{"publisher":{"const":"北京航空航天大学"},"directory_label":{"const":"教学科研机构"},"source_url":{"const":ORGANIZATIONS_URL}}},
                "document_title":{"type":"string"},"categories":{"type":"array","minItems":1,"maxItems":MAX_GROUPS,"items":{"type":"string"}},
                "entries":{"type":"array","minItems":1,"maxItems":MAX_ENTRIES,"items":{"type":"object","additionalProperties":false,"required":["source_order","category","name","listed_href","resolved_http_url","link_kind","hidden_in_source"],"properties":{"source_order":{"type":"integer","minimum":1},"category":{"type":"string"},"name":{"type":"string"},"listed_href":{"type":["string","null"]},"resolved_http_url":{"type":["string","null"]},"link_kind":{"enum":["http","https","missing","non_http","invalid"]},"hidden_in_source":{"type":"boolean"}}}},
                "completeness":{"type":"object","additionalProperties":false,"required":["scope","includes_hidden_source_entries","entry_count","category_count","university_wide_beyond_this_document"],"properties":{"scope":{"const":"entries_in_captured_official_directory_document"},"includes_hidden_source_entries":{"const":true},"entry_count":{"type":"integer","minimum":1},"category_count":{"type":"integer","minimum":1},"university_wide_beyond_this_document":{"const":false}}},
                "retrieval":{"type":"object","additionalProperties":false,"required":["source_url","fetched_at_unix_ms","cache_status","revalidated_at_unix_ms","revalidation_status","response_body_sha256","response_body_byte_length","http"],"properties":{"source_url":{"const":ORGANIZATIONS_URL},"fetched_at_unix_ms":{"type":"integer","minimum":0},"cache_status":{"enum":["hit","miss","revalidated"]},"revalidated_at_unix_ms":{"type":["integer","null"],"minimum":0},"revalidation_status":{"type":["integer","null"]},"response_body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"response_body_byte_length":{"type":"integer","minimum":0},"http":{"type":"object","additionalProperties":false,"required":["status","headers"],"properties":{"status":{"const":200},"headers":{"type":"object","additionalProperties":{"type":"string"}}}}}}
            }
        }
    }});
    let mut snapshot = schema["list"]["output"].take();
    let mut retrieval = snapshot["properties"]["retrieval"].take();
    retrieval["properties"]["http"]["properties"]["headers_withheld"] = json!({"type":"boolean"});
    snapshot["properties"]["retrieval"] = json!({"$ref":"#/$defs/retrieval"});
    snapshot["properties"]["entries"]["items"]["properties"]["hidden_in_source"]["description"] =
        json!("Source hidden markers or unresolved inline visibility; not computed browser layout.");
    schema["list"]["output"] = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "$defs":{"retrieval":retrieval},
        "oneOf":[snapshot,{
            "type":"object","additionalProperties":false,
            "description":"Legacy provenance is metadata-only. Known cookie-free, privacy-admitted originals with selector drift include exact raw HTML. No degraded result authorizes members.",
            "required":["schema_version","type","result","authority","entries","raw_html","raw_withheld","raw_withheld_reason","raw_html_sha256","content_type","body_byte_length","fallback_reason","retrieval"],
            "properties":{
                "schema_version":{"const":1},"type":{"const":"organization_directory"},"result":{"const":"fallback"},
                "authority":{"type":"object","additionalProperties":false,"required":["publisher","directory_label","source_url"],"properties":{"publisher":{"const":"北京航空航天大学"},"directory_label":{"const":"教学科研机构"},"source_url":{"const":ORGANIZATIONS_URL}}},
                "entries":{"type":"array","maxItems":0},
                "raw_html":{"type":["string","null"],"contentEncoding":"base64"},
                "raw_withheld":{"type":"boolean"},
                "raw_withheld_reason":{"enum":[null,"cookie_provenance_unavailable"]},
                "raw_html_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "content_type":{"const":"text/html"},
                "body_byte_length":{"type":"integer","minimum":1,"maximum":MAX_HTML},
                "fallback_reason":{"enum":["organization_directory_provenance_unknown","organization_directory_selector_contract"]},
                "retrieval":{"$ref":"#/$defs/retrieval"}
            },
            "oneOf":[
                {"properties":{"raw_html":{"type":"string"},"raw_withheld":{"const":false},"raw_withheld_reason":{"type":"null"},"fallback_reason":{"const":"organization_directory_selector_contract"}}},
                {"properties":{"raw_html":{"type":"null"},"raw_withheld":{"const":true},"raw_withheld_reason":{"const":"cookie_provenance_unavailable"},"fallback_reason":{"const":"organization_directory_provenance_unknown"}}}
            ]
        }]
    });
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn body_sha256(body: &[u8]) -> String {
        format!("{:x}", Sha256::digest(body))
    }

    fn response(body: &[u8]) -> Response {
        Response {
            url: ORGANIZATIONS_URL.to_owned(),
            status: 200,
            headers: [("content-type".into(), "text/html".into())].into(),
            body: body.to_vec(),
            sha256: body_sha256(body),
            fetched_at_unix_ms: 1,
            cache_status: crate::net::CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }

    fn directory(member: &str) -> String {
        format!("<html><title>Official</title><div class='kyjg-box'><div class='kyjg-tit'><h3>Group</h3></div><div class='kyjg-bd'>{member}</div></div></html>")
    }

    #[test]
    fn directory_active_bases_cannot_change_source_member_resolution() {
        let directory = directory("<a href='/relative'>Fixture</a>");
        for base in [
            "<base href='https://foreign.example/'>",
            "<base href='https://www.buaa.edu.cn/'>",
        ] {
            assert_eq!(parse_html(format!("{base}{directory}").as_bytes()).unwrap_err().code,
                "unavailable");
        }
        let inert = format!("<template><base href='https://foreign.example/'></template><noscript><base href='https://foreign.example/'></noscript>{directory}");
        let parsed = parse_html(inert.as_bytes()).unwrap();
        assert_eq!(parsed.entries[0].resolved_http_url.as_deref(),
            Some("https://www.buaa.edu.cn/relative"));
    }

    #[test]
    fn directory_source_metadata_requires_exact_html_mime() {
        let body = directory("<a href='https://one.buaa.edu.cn/'>One</a>");
        let mut response = response(body.as_bytes());
        for content_type in [None, Some("text/plain"), Some("text/html-unknown"),
            Some("text/html\u{00a0}"), Some("text/html\n"), Some("text/html\u{000b}")] {
            response.headers.clear();
            if let Some(value) = content_type {
                response.headers.insert("content-type".into(), value.into());
            }
            assert_eq!(normalize(&response, CookieAdmission::CookieFree).unwrap_err().code,
                "unavailable", "{content_type:?}");
        }
        for value in ["text/html; charset=utf-8", "TeXt/HtMl; charset=utf-8"] {
            response.headers.insert("content-type".into(), value.into());
            assert_eq!(normalize(&response, CookieAdmission::CookieFree).unwrap()["result"],
                "directory_snapshot", "{value:?}");
        }
        assert!(parse_html(&[0xff]).is_err());
    }

    #[test]
    fn hidden_source_markers_resolve_comments_and_inline_cascade() {
        for style in ["display:none", "/*x*/display:none", "display:/*x*/none",
            "display:none /*x*/", "display:none!important;display:block",
            "display:block;display:none", "display:none!important;display:block!important;display:none!important",
            "visibility:hidden", "visibility:collapse", "content-visibility:hidden",
            "display:none;all:initial", "display:var(--x)", "display:none;/*unclosed"] {
            let input = directory(&format!("<div style='{style}'><a href='/x'>Fixture</a></div>"));
            assert!(parse_html(input.as_bytes()).unwrap().entries[0].hidden_in_source, "{style}");
        }
        for style in ["x-display:none", "display:none2", "display:none;display:block",
            "display:none;display:block!important", "display:none!important;display:block!important",
            "visibility:hidden;visibility:visible", "visibility:visible", "color:red"] {
            let input = directory(&format!("<div style='{style}'><a href='/x'>Fixture</a></div>"));
            assert!(!parse_html(input.as_bytes()).unwrap().entries[0].hidden_in_source, "{style}");
        }
        for attributes in ["hidden", "class='xbt'"] {
            let input = directory(&format!("<div {attributes}><a style='display:block;visibility:visible' href='/x'>Fixture</a></div>"));
            assert!(parse_html(input.as_bytes()).unwrap().entries[0].hidden_in_source);
        }
        for attributes in ["class='xbtx'", "data-hidden='true'"] {
            let input = directory(&format!("<div {attributes}><a href='/x'>Fixture</a></div>"));
            assert!(!parse_html(input.as_bytes()).unwrap().entries[0].hidden_in_source);
        }
    }

    #[test]
    fn nearest_visibility_can_reveal_but_subtree_hiding_cannot() {
        for ancestor in ["visibility:hidden", "visibility:hidden!important", "visibility:collapse"] {
            let input = directory(&format!("<div style='{ancestor}'><span><a style='visibility:visible' href='/x'>Fixture</a></span></div>"));
            assert!(!parse_html(input.as_bytes()).unwrap().entries[0].hidden_in_source, "{ancestor}");
        }
        for ancestor in ["display:none", "display:none!important", "content-visibility:hidden"] {
            let input = directory(&format!("<div style='{ancestor}'><a style='display:block;visibility:visible' href='/x'>Fixture</a></div>"));
            assert!(parse_html(input.as_bytes()).unwrap().entries[0].hidden_in_source, "{ancestor}");
        }
    }

    #[test]
    fn safe_drift_exports_exact_original_with_real_digest() {
        let body = b"<html><title>Public fixture</title><p>Ordinary public prose.</p><script>var n=1;</script></html>";
        let output = normalize(&response(body), CookieAdmission::CookieFree).unwrap();
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["fallback_reason"], "organization_directory_selector_contract");
        assert_eq!(output["entries"], json!([]));
        assert_eq!(output["raw_withheld"], false);
        assert_eq!(output["raw_withheld_reason"], Value::Null);
        let decoded = STANDARD.decode(output["raw_html"].as_str().unwrap()).unwrap();
        assert_eq!(decoded.as_slice(), body.as_slice());
        assert_eq!(output["raw_html_sha256"], body_sha256(&decoded));
        assert_eq!(output["retrieval"]["response_body_sha256"], body_sha256(&decoded));
        assert_eq!(output["body_byte_length"], decoded.len());
        assert_eq!(output["content_type"], "text/html");
    }

    #[test]
    fn legacy_unknown_never_projects_opaque_body_or_header_values() {
        let private_marker = "opaqueFixturePrivate42";
        let body = directory(&format!("<a href='/x'>{private_marker}</a>"));
        let mut response = response(body.as_bytes());
        response.headers.insert("etag".into(), format!("\"{private_marker}\""));
        response.headers.insert("content-type".into(), format!("text/html; note={private_marker}"));
        let output = normalize(&response, CookieAdmission::Unknown).unwrap();
        assert_eq!(output["result"], "fallback");
        assert_eq!(output["fallback_reason"], "organization_directory_provenance_unknown");
        assert_eq!(output["entries"], json!([]));
        assert_eq!(output["raw_html"], Value::Null);
        assert_eq!(output["raw_withheld"], true);
        assert_eq!(output["raw_withheld_reason"], "cookie_provenance_unavailable");
        assert_eq!(output["retrieval"]["http"]["headers"], json!({}));
        assert_eq!(output["retrieval"]["http"]["headers_withheld"], true);
        assert_eq!(output["content_type"], "text/html");
        assert!(output.get("document_title").is_none());
        assert!(output.get("categories").is_none());
        assert!(!output.to_string().contains(private_marker));
    }

    #[test]
    fn sensitive_attributes_and_raw_payloads_refuse_before_any_projection() {
        for markup in [
            "<form action='/login'><input type='password' name='password'></form>",
            "<input type='hidden' name='csrf_token'>",
            "<div id='cf-challenge-form'></div>",
            "<script>const csrfToken='fixturePrivate42';</script>",
            "<script type=\"application/json\">{\"authenticity_token\":\"fixturePrivate42\"}</script>",
            "<script type=\"application/json\">{\"passwd\":\"fixturePrivate42\"}</script>",
            "<!-- password=fixturePrivate42 -->",
            "<style>/*csrfToken=fixturePrivate42*/</style>",
            "<p>password=fixturePrivate42</p>",
            "<div id='public' id='csrfToken42'>Text</div>",
            "<p title='public' title='c&#115;rfToken=fixturePrivate42'>Text</p>",
            "<p title='public' title='p&#x61;ssword=fixturePrivate42'>Text</p>",
        ] {
            for body in [format!("<title>Drift</title>{markup}"),
                directory(&format!("<a href='/x'>One</a>{markup}"))] {
                let error = normalize(&response(body.as_bytes()), CookieAdmission::CookieFree)
                    .unwrap_err();
                assert_eq!(error.code, "unavailable", "{markup}");
                assert!(!error.message.contains("fixturePrivate42"));
            }
        }
    }

    #[test]
    fn parses_visible_hidden_missing_and_non_http_entries_without_guessing() {
        let input = r#"<!doctype html><html><head><title>教学科研机构-北京航空航天大学</title></head><body>
        <div class='kyjg-box'><div class='kyjg-tit'><h3>学科群 A</h3></div><div class='kyjg-bd'><ul>
        <li><a href=' http://one.buaa.edu.cn '>学院一<em></em></a><a class='xbt' style='display:none' href='https://hidden.buaa.edu.cn/'>隐藏研究院</a></li>
        <li><a>待建研究院</a></li><li><a href='javascript:void(0)'>无页面学院</a></li></ul></div></div>
        <div class='kyjg-box'><div class='kyjg-tit'><h3>学科群 B</h3></div><div class='kyjg-bd'><a href='/relative'>相对链接学院</a></div></div>
        </body></html>"#;
        let parsed = parse_html(input.as_bytes()).unwrap();
        assert_eq!(parsed.categories, ["学科群 A", "学科群 B"]);
        assert_eq!(parsed.entries.len(), 5);
        assert_eq!(
            parsed.entries[0].listed_href.as_deref(),
            Some(" http://one.buaa.edu.cn ")
        );
        assert_eq!(
            parsed.entries[0].resolved_http_url.as_deref(),
            Some("http://one.buaa.edu.cn/")
        );
        assert!(parsed.entries[1].hidden_in_source);
        assert_eq!(parsed.entries[2].link_kind, "missing");
        assert_eq!(parsed.entries[3].link_kind, "non_http");
        assert_eq!(
            parsed.entries[4].resolved_http_url.as_deref(),
            Some("https://www.buaa.edu.cn/relative")
        );
        assert_eq!(parsed.entries[4].source_order, 5);
    }

    #[test]
    fn inactive_directory_declarations_cannot_supply_college_identity() {
        let inert_only = "<html><title>Directory</title><div class='kyjg-box'><div class='kyjg-tit'><h3>Group</h3></div><div class='kyjg-bd'><template><a href='http://mse.buaa.edu.cn/'>材料科学与工程学院</a></template></div></div></html>";
        assert_eq!(
            parse_html(inert_only.as_bytes()).unwrap_err().code,
            "unavailable"
        );

        let active = "<html><title>Directory</title><template><div class='kyjg-box'><div class='kyjg-tit'><h3>Inactive group</h3></div><div class='kyjg-bd'><a href='https://inactive.example/'>Inactive college</a></div></div></template><div class='kyjg-box'><div class='kyjg-tit'><template><h3>Inactive heading</h3></template><h3>Active Group<noscript>Inactive suffix</noscript></h3></div><div class='kyjg-bd'><template><a href='http://mse.buaa.edu.cn/'>Inactive duplicate</a></template><a href='http://mse.buaa.edu.cn/'>材料科学与工程学院<script>Inactive code</script><template>Inactive label</template></a></div></div></html>";
        let parsed = parse_html(active.as_bytes()).unwrap();
        assert_eq!(parsed.categories, ["Active Group"]);
        assert_eq!(
            parsed
                .entries
                .iter()
                .map(|entry| (
                    entry.name.as_str(),
                    entry.listed_href.as_deref(),
                    entry.resolved_http_url.as_deref()
                ))
                .collect::<Vec<_>>(),
            [(
                "材料科学与工程学院",
                Some("http://mse.buaa.edu.cn/"),
                Some("http://mse.buaa.edu.cn/")
            )]
        );
    }

    #[test]
    fn normalized_output_binds_counts_and_retrieval_provenance() {
        let body = b"<html><title>Official</title><div class='kyjg-box'><div class='kyjg-tit'><h3>Group</h3></div><div class='kyjg-bd'><a href='https://one.buaa.edu.cn/'>One</a></div></div></html>";
        let response = Response {
            url: ORGANIZATIONS_URL.to_owned(),
            status: 200,
            headers: [("content-type".to_owned(), "text/html".to_owned())].into(),
            body: body.to_vec(),
            sha256: body_sha256(body),
            fetched_at_unix_ms: 1,
            cache_status: crate::net::CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        let output = normalize(&response, CookieAdmission::CookieFree).unwrap();
        assert_eq!(output["completeness"]["entry_count"], 1);
        assert_eq!(output["completeness"]["category_count"], 1);
        assert_eq!(
            output["entries"][0]["resolved_http_url"],
            "https://one.buaa.edu.cn/"
        );
        assert_eq!(output["retrieval"]["response_body_sha256"], body_sha256(body));
        assert_eq!(output["retrieval"]["source_url"], ORGANIZATIONS_URL);
        let mut wrong = response;
        wrong.url = "https://www.buaa.edu.cn/".into();
        assert!(normalize(&wrong, CookieAdmission::CookieFree).is_err());
    }
    #[test]
    fn rejects_unscoped_or_unbounded_documents() {
        assert!(parse_html(b"<html><title>x</title></html>").is_err());
        assert!(parse_html(&vec![b'x'; MAX_HTML + 1]).is_err());
        let control = b"<html><title>x</title><div class=kyjg-box><div class=kyjg-tit><h3>A</h3></div><div class=kyjg-bd><a href='https://a.example'>bad\x01name</a></div></div></html>";
        assert!(parse_html(control).is_err());
        let empty_group = b"<html><title>x</title><div class=kyjg-box><div class=kyjg-tit><h3>Empty</h3></div><div class=kyjg-bd></div></div><div class=kyjg-box><div class=kyjg-tit><h3>Valid</h3></div><div class=kyjg-bd><a href='https://a.example'>ok</a></div></div></html>";
        assert!(parse_html(empty_group).is_err());
        let category_control = b"<html><title>x</title><div class=kyjg-box><div class=kyjg-tit><h3>bad\x01group</h3></div><div class=kyjg-bd><a href='https://a.example'>ok</a></div></div></html>";
        assert!(parse_html(category_control).is_err());
    }
}

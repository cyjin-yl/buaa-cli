//! Read-only SPOC public surface observation.
//!
//! This is contract-evidence tooling for the SPOC acceptance item, not an
//! authenticated adapter. It fetches fixed public paths through the shared
//! process governor (robots policy checked first), and reports only sanitized
//! structural facts: status, content type, byte length, SHA-256, document
//! title and form shape. Response bodies, input names and values never enter
//! the output, logs or repository. No authentication is attempted.
use crate::net::{ArchiveClient, CacheMode, Error, Response, SPOC_ENTRY_URL, SPOC_ROOT_URL};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const MAX_HTML: usize = 2 * 1024 * 1024;
const MAX_TITLE: usize = 512;
const MAX_FORMS: usize = 16;
const MAX_ACTION: usize = 4096;

const SURFACE_PAGES: [(&str, &str); 2] = [(SPOC_ROOT_URL, "root"), (SPOC_ENTRY_URL, "entry")];

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "SPOC public surface could not be interpreted safely",
    )
}

fn normalized_text<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Describe one fetched public page as sanitized structural facts. The body
/// itself is never included in the returned value.
pub fn describe_page(response: &Response, label: &str) -> Result<Value, Error> {
    if response.status != 200 {
        return Err(unavailable());
    }
    if response
        .headers
        .get("content-type")
        .is_some_and(|value| !value.to_ascii_lowercase().starts_with("text/html"))
    {
        return Err(unavailable());
    }
    if response.body.len() > MAX_HTML {
        return Err(unavailable());
    }
    let input = std::str::from_utf8(&response.body).map_err(|_| unavailable())?;
    let document = Html::parse_document(input);
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let form_selector = Selector::parse("form").map_err(|_| unavailable())?;
    let field_selector = Selector::parse("input, select, textarea").map_err(|_| unavailable())?;
    let title = match document
        .select(&title_selector)
        .next()
        .map(|element| normalized_text(element.text()))
    {
        Some(value) if value.is_empty() => None,
        Some(value) if value.len() <= MAX_TITLE => Some(value),
        Some(_) => return Err(unavailable()),
        None => None,
    };
    let mut forms = Vec::new();
    for element in document.select(&form_selector) {
        if forms.len() == MAX_FORMS {
            return Err(unavailable());
        }
        let action = element
            .value()
            .attr("action")
            .map(str::trim)
            .unwrap_or_default();
        if action.len() > MAX_ACTION || action.chars().any(char::is_control) {
            return Err(unavailable());
        }
        forms.push(json!({
            "action": if action.is_empty() { None } else { Some(action) },
            "field_count": element.select(&field_selector).count(),
        }));
    }
    Ok(json!({
        "label": label,
        "url": response.url,
        "status": response.status,
        "content_type": response.headers.get("content-type").cloned(),
        "body_byte_length": response.body.len(),
        "body_sha256": response.sha256,
        "title": title,
        "forms": forms,
        "retrieval": {
            "fetched_at_unix_ms": response.fetched_at_unix_ms,
            "cache_status": response.cache_status,
            "revalidated_at_unix_ms": response.revalidated_at_unix_ms,
            "revalidation_status": response.revalidation_status
        }
    }))
}

pub fn surface(mode: CacheMode) -> Result<Value, Error> {
    let client = ArchiveClient::open_spoc(mode)?;
    let mut pages = Vec::new();
    for (url_str, label) in SURFACE_PAGES {
        let url = Url::parse(url_str).map_err(|_| unavailable())?;
        pages.push(client.get(&url, false, |response| describe_page(response, label))?);
    }
    Ok(json!({
        "schema_version": 1,
        "type": "spoc_public_surface",
        "result": "surface_snapshot",
        "authority": {
            "publisher": "北京航空航天大学",
            "source_urls": SURFACE_PAGES.iter().map(|(url, _)| *url).collect::<Vec<_>>(),
            "scope": "public surface only; no authentication, no private content, no mutation"
        },
        "pages": pages
    }))
}

fn form_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["action","field_count"],
        "properties":{"action":{"type":["string","null"]},"field_count":{"type":"integer","minimum":0}}
    })
}

fn page_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "required":["label","url","status","content_type","body_byte_length","body_sha256","title","forms","retrieval"],
        "properties":{
            "label":{"enum":["root","entry"]},
            "url":{"type":"string"},
            "status":{"const":200},
            "content_type":{"type":["string","null"]},
            "body_byte_length":{"type":"integer","minimum":0},
            "body_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "title":{"type":["string","null"]},
            "forms":{"type":"array","maxItems":MAX_FORMS,"items":form_schema()},
            "retrieval":{"type":"object","additionalProperties":false,"required":["fetched_at_unix_ms","cache_status","revalidated_at_unix_ms","revalidation_status"],"properties":{"fetched_at_unix_ms":{"type":"integer","minimum":0},"cache_status":{"enum":["hit","miss","revalidated"]},"revalidated_at_unix_ms":{"type":["integer","null"],"minimum":0},"revalidation_status":{"type":["integer","null"]}}}
        }
    })
}

pub fn schema() -> Value {
    json!({
        "surface": {
            "input": {"type":"null","description":"No stdin. Default is private cache only; --online and --refresh are explicit options."},
            "output": {
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object","additionalProperties":false,
                "required":["schema_version","type","result","authority","pages"],
                "properties":{
                    "schema_version":{"const":1},"type":{"const":"spoc_public_surface"},"result":{"const":"surface_snapshot"},
                    "authority":{"type":"object","additionalProperties":false,"required":["publisher","source_urls","scope"],"properties":{"publisher":{"const":"北京航空航天大学"},"source_urls":{"type":"array","minItems":2,"maxItems":2,"items":{"type":"string"}},"scope":{"const":"public surface only; no authentication, no private content, no mutation"}}},
                    "pages":{"type":"array","minItems":2,"maxItems":2,"items":page_schema()}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheStatus;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    fn response(status: u16, content_type: &str, body: &str) -> Response {
        let bytes = body.as_bytes().to_vec();
        let sha = format!("{:x}", Sha256::digest(&bytes));
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), content_type.to_owned());
        Response {
            url: SPOC_ROOT_URL.to_owned(),
            status,
            headers,
            body: bytes,
            sha256: sha,
            fetched_at_unix_ms: 1,
            cache_status: CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        }
    }
    const PAGE: &str = r#"<html><head><title>SPOC 门户</title></head><body>
        <form action="/login" method="post"><input name="a"/><input name="b"/></form>
        <form><select name="c"></select></form>
    </body></html>"#;

    #[test]
    fn describes_public_page_as_sanitized_facts() {
        let value =
            describe_page(&response(200, "text/html; charset=utf-8", PAGE), "root").unwrap();
        assert_eq!(value["label"], "root");
        assert_eq!(value["title"], "SPOC 门户");
        assert_eq!(value["forms"].as_array().unwrap().len(), 2);
        assert_eq!(value["forms"][0]["action"], "/login");
        assert_eq!(value["forms"][0]["field_count"], 2);
        assert_eq!(value["forms"][1]["action"], Value::Null);
        assert_eq!(value["forms"][1]["field_count"], 1);
        // The body and its field names must never appear in the output.
        let rendered = value.to_string();
        assert!(!rendered.contains("name=\"a\""));
        assert!(!rendered.contains("<body>"));
        assert!(value.get("body").is_none());
    }

    #[test]
    fn rejects_non_success_and_non_html() {
        assert!(describe_page(&response(404, "text/html", PAGE), "root").is_err());
        assert!(describe_page(&response(200, "application/json", "{}"), "root").is_err());
    }

    #[test]
    fn rejects_oversized_and_unsafe_structure() {
        let page = format!(
            "<html><head><title>{}</title></head><body></body></html>",
            "x".repeat(MAX_TITLE + 1)
        );
        assert!(describe_page(&response(200, "text/html", &page), "root").is_err());
        let action = format!("a{}b", char::from_u32(1).unwrap());
        let page = format!(
            "<html><head><title>t</title></head><body><form action=\"{action}\"></form></body></html>"
        );
        assert!(describe_page(&response(200, "text/html", &page), "root").is_err());
        let mut forms = String::new();
        for _ in 0..=MAX_FORMS {
            forms.push_str("<form></form>");
        }
        let page = format!("<html><head><title>t</title></head><body>{forms}</body></html>");
        assert!(describe_page(&response(200, "text/html", &page), "root").is_err());
    }
}

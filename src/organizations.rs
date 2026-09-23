//! Authoritative organization directory parsing over one fixed official source.
use crate::net::{ArchiveClient, CacheMode, Error, ORGANIZATIONS_URL, Response};
use scraper::{Html, Selector};
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

fn normalized_text<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse the official directory document. This is public for offline evidence
/// validation and library consumers; it performs no network or cache access.
pub fn parse_html(bytes: &[u8]) -> Result<DirectoryDocument, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let input = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(input);
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let box_selector = Selector::parse(".kyjg-box").map_err(|_| unavailable())?;
    let category_selector = Selector::parse(".kyjg-tit h3").map_err(|_| unavailable())?;
    let entry_selector = Selector::parse(".kyjg-bd a").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(|element| normalized_text(element.text()))
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(unavailable)?;
    let base = Url::parse(ORGANIZATIONS_URL).map_err(|_| unavailable())?;
    let mut categories = Vec::new();
    let mut seen_categories = BTreeSet::new();
    let mut entries = Vec::new();
    for group in document.select(&box_selector) {
        let category = group
            .select(&category_selector)
            .next()
            .map(|element| normalized_text(element.text()))
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
            if entries.len() == MAX_ENTRIES {
                return Err(unavailable());
            }
            let name = normalized_text(element.text());
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
            let classes = element
                .value()
                .attr("class")
                .unwrap_or_default()
                .split_whitespace();
            let style = element
                .value()
                .attr("style")
                .unwrap_or_default()
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .flat_map(char::to_lowercase)
                .collect::<String>();
            entries.push(Organization {
                source_order: entries.len() + 1,
                category: category.clone(),
                name,
                listed_href,
                resolved_http_url,
                link_kind,
                hidden_in_source: classes.into_iter().any(|class| class == "xbt")
                    || style.contains("display:none"),
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

fn normalize(response: &Response) -> Result<Value, Error> {
    if response.url != ORGANIZATIONS_URL || response.status != 200 {
        return Err(unavailable());
    }
    if response
        .headers
        .get("content-type")
        .is_some_and(|value| !value.to_ascii_lowercase().starts_with("text/html"))
    {
        return Err(unavailable());
    }
    let parsed = parse_html(&response.body)?;
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

pub fn list(mode: CacheMode) -> Result<Value, Error> {
    let client = ArchiveClient::open_organizations(mode)?;
    let url = Url::parse(ORGANIZATIONS_URL).map_err(|_| unavailable())?;
    client.get(&url, false, normalize)
}

pub fn schema() -> Value {
    json!({"list": {
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
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn normalized_output_binds_counts_and_retrieval_provenance() {
        let body = b"<html><title>Official</title><div class='kyjg-box'><div class='kyjg-tit'><h3>Group</h3></div><div class='kyjg-bd'><a href='https://one.buaa.edu.cn/'>One</a></div></div></html>";
        let response = Response {
            url: ORGANIZATIONS_URL.to_owned(),
            status: 200,
            headers: [("content-type".to_owned(), "text/html".to_owned())].into(),
            body: body.to_vec(),
            sha256: "a".repeat(64),
            fetched_at_unix_ms: 1,
            cache_status: crate::net::CacheStatus::Miss,
            revalidated_at_unix_ms: None,
            revalidation_status: None,
        };
        let output = normalize(&response).unwrap();
        assert_eq!(output["completeness"]["entry_count"], 1);
        assert_eq!(output["completeness"]["category_count"], 1);
        assert_eq!(
            output["entries"][0]["resolved_http_url"],
            "https://one.buaa.edu.cn/"
        );
        assert_eq!(output["retrieval"]["response_body_sha256"], "a".repeat(64));
        assert_eq!(output["retrieval"]["source_url"], ORGANIZATIONS_URL);
        let mut wrong = response;
        wrong.url = "https://www.buaa.edu.cn/".into();
        assert!(normalize(&wrong).is_err());
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

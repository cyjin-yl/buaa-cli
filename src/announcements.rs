//! Official BUAA news-center announcement listing (`xwzx.htm`), parsed over a
//! cache-first snapshot shared with the official-directory governor policy.
//!
//! The parser intentionally understands only the reviewed structure: one
//! `.xwzx-list li` row per announcement, an `a[href]` anchor whose text is the
//! title and an embedded `.xwzx-date` in `YYYY-MM-DD`. Entries missing a title
//! or date are rejected rather than reconstructed. All attachment/正文 fetch,
//! pagination beyond page 1, and linked-college crawling stay out of scope.

use crate::net::{ArchiveClient, CacheMode, Error};
use scraper::{Html, Selector};
use serde_json::{Value, json};
use url::Url;

const ANNOUNCEMENTS_URL: &str = "https://www.buaa.edu.cn/xwzx.htm";
const MAX_HTML: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
const MAX_TEXT: usize = 512;
const MAX_HREF: usize = 4096;

#[derive(Debug, serde::Serialize)]
pub struct AnnouncementEntry {
    pub source_order: usize,
    pub title: String,
    pub date: String,
    pub listed_href: Option<String>,
    pub resolved_http_url: Option<String>,
    pub link_kind: &'static str,
}

#[derive(Debug, serde::Serialize)]
pub struct AnnouncementsDocument {
    pub title: String,
    pub entries: Vec<AnnouncementEntry>,
}

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "official news-center listing could not be interpreted safely; file an issue at https://github.com/cyjin-yl/buaa-cli/issues/new with this CLI version and URL",
    )
}

/// Emit a rejected-parse error anchored to a declared invariant, so an
/// operator-agent can file a GitHub issue or debug-and-patch the listed
/// invariant and open a PR.
fn failed_contract(invariant: &'static str, file: &'static str, line: u32) -> Error {
    Error::with_source(
        "unavailable",
        "official news-center listing contract violated; the public page layout likely changed. File an issue at https://github.com/cyjin-yl/buaa-cli/issues/new or debug the reported invariant yourself and open a PR",
        file,
        line,
        invariant,
    )
}

fn normalized_text<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    parts
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_date(raw: &str) -> Result<String, Error> {
    let mut parts = raw.split('-');
    let year = parts.next().and_then(|p| p.parse::<i32>().ok());
    let month = parts.next().and_then(|p| p.parse::<u32>().ok());
    let day = parts.next().and_then(|p| p.parse::<u32>().ok());
    if parts.next().is_some() {
        return Err(unavailable());
    }
    match (year, month, day) {
        (Some(y), Some(m), Some(d))
            if (1970..=2100).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d) =>
        {
            Ok(format!("{y:04}-{m:02}-{d:02}"))
        }
        _ => Err(failed_contract(
            "announcement date must be yyyy-mm-dd with gross bounds",
            file!(),
            line!(),
        )),
    }
}

/// Parse one news-center listing document. This is public for offline
/// evidence validation; it performs no network or cache access.
pub fn parse_html(bytes: &[u8]) -> Result<AnnouncementsDocument, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let input = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(input);
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let row_selector = Selector::parse(".xwzx-list li").map_err(|_| unavailable())?;
    let anchor_selector = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let date_selector = Selector::parse(".xwzx-date").map_err(|_| unavailable())?;

    let title = document
        .select(&title_selector)
        .next()
        .map(|element| normalized_text(element.text()))
        .filter(|value| !value.is_empty() && value.len() <= MAX_TEXT)
        .ok_or_else(|| {
            failed_contract("document title must exist, fit 1..max", file!(), line!())
        })?;

    let base = Url::parse(ANNOUNCEMENTS_URL).map_err(|_| unavailable())?;
    let mut entries = Vec::new();
    for row in document.select(&row_selector) {
        let anchor = row.select(&anchor_selector).next().ok_or_else(|| {
            failed_contract(
                "announcement row must contain a[href] anchor",
                file!(),
                line!(),
            )
        })?;
        let title_text = normalized_text(anchor.text());
        if title_text.is_empty() || title_text.len() > MAX_TEXT {
            return Err(failed_contract(
                "announcement title must fit 1..max bytes",
                file!(),
                line!(),
            ));
        }
        let date = row
            .select(&date_selector)
            .next()
            .map(|element| normalized_text(element.text()))
            .ok_or_else(|| {
                failed_contract("announcement row must contain .xwzx-date", file!(), line!())
            })?;
        let date = parse_date(&date)?;

        let listed_href = anchor.attr("href").map(str::to_owned);
        let (resolved_http_url, link_kind) = match listed_href.as_deref() {
            None => (None, "missing"),
            Some(raw) => {
                if raw.len() > MAX_HREF {
                    return Err(unavailable());
                }
                match base.join(raw) {
                    Ok(resolved) => {
                        if resolved.scheme() == "http" || resolved.scheme() == "https" {
                            let normalized = normalized_text(std::iter::once(resolved.as_str()));
                            (Some(normalized), "http")
                        } else {
                            (None, "non_http")
                        }
                    }
                    Err(_) => (None, "invalid"),
                }
            }
        };
        if entries.len() >= MAX_ENTRIES {
            return Err(unavailable());
        }
        entries.push(AnnouncementEntry {
            source_order: entries.len() + 1,
            title: title_text,
            date,
            listed_href,
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "announcement document must contain at least one .xwzx-list li row",
            file!(),
            line!(),
        ));
    }
    Ok(AnnouncementsDocument { title, entries })
}

fn retrieval(response: &crate::net::Response) -> Value {
    json!({
        "source_url": ANNOUNCEMENTS_URL,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "cache_status": response.cache_status,
        "response_body_sha256": response.sha256,
        "response_body_byte_length": response.body.len(),
        "http": {"status": response.status, "headers": response.headers},
    })
}

fn normalize(response: &crate::net::Response) -> Result<Value, Error> {
    let document = parse_html(response.body.as_slice())?;
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_list",
        "result": "listing_snapshot",
        "publisher": "北京航空航天大学",
        "listing_label": "新闻中心",
        "document_title": document.title,
        "entries": document.entries,
        "completeness": {
            "scope": "page_1_of_official_news_center",
            "pagination": "not_followed",
            "historical_content": "use_buaa_archive",
        },
        "retrieval": retrieval(response),
    }))
}

pub fn list(mode: CacheMode) -> Result<Value, Error> {
    let client = ArchiveClient::open_announcements(mode)?;
    let url = Url::parse(ANNOUNCEMENTS_URL).map_err(|_| unavailable())?;
    client.get(&url, false, normalize)
}

/// Parse a bounded Web Archive snapshot of the listing page and return the
/// same shape as `list`, without writing to a live-cache slot. The caller
/// supplies the archived bytes via stdin (e.g. produced by an `archive capture`
/// step) so probe pacing remains governed and reads stay offline by default.
pub fn history_parse(bytes: &[u8]) -> Result<Value, Error> {
    let document = parse_html(bytes)?;
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_list",
        "result": "listing_snapshot",
        "publisher": "北京航空航天大学",
        "listing_label": "新闻中心（历史快照）",
        "document_title": document.title,
        "entries": document.entries,
        "completeness": {
            "scope": "single_supplied_archive_snapshot",
            "pagination": "not_applicable",
            "freshness": "archived_bytes",
        },
        "retrieval": null,
    }))
}

pub fn schema() -> Value {
    json!({
        "list": {
            "input": {"type":"null","description":"No stdin. Default is private cache only; --online and --refresh are explicit options."},
            "output": {
                "type":"object",
                "required":["schema_version","type","result","publisher","listing_label","document_title","entries","completeness","retrieval"],
                "properties": {
                    "schema_version":{"const":1},
                    "type":{"const":"announcements_list"},
                    "result":{"const":"listing_snapshot"},
                    "entries":{"type":"array","maxItems":MAX_ENTRIES}
                }
            },
            "source_url": ANNOUNCEMENTS_URL,
            "policy": "Authoritative news-center index only; historical pages stay on the archive path; no attachment/crawl expansion."
        },
        "history": {
            "input": {
                "type":"string",
                "format":"utf-8-html-bytes",
                "description":"Bounded Web Archive snapshot bytes supplied on stdin (e.g. from `buaa archive capture`); parser performs no network."
            },
            "output": {
                "type":"object",
                "required":["schema_version","type","result","publisher","listing_label","document_title","entries","completeness","retrieval"],
                "properties": {
                    "schema_version":{"const":1},
                    "type":{"const":"announcements_list"},
                    "result":{"const":"listing_snapshot"},
                    "retrieval":{"type":"null"}
                }
            },
            "policy": "Operator-supplied bytes only; no attacker-controlled path or archive redirect chain."
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::CacheMode;

    fn fixture_html(entries: &str) -> Vec<u8> {
        format!(
            r#"<!doctype html><html><head><title>新闻中心-北航</title></head>
<body><ul class="xwzx-list">{entries}</ul></body></html>"#
        )
        .into_bytes()
    }

    fn li(title: &str, date: &str, href: Option<&str>) -> String {
        let href_attr = href.map_or(String::new(), |value| format!(r##" href="{value}""##));
        format!(r#"<li><a{href_attr}>{title}</a><span class="xwzx-date">{date}</span></li>"#)
    }

    #[test]
    fn parses_listing_with_absolute_relative_and_missing_links() {
        let html = fixture_html(&format!(
            "{}{}",
            li("通知一", "2026-09-20", Some("xwzx/2026/01.htm")),
            li("通知二", "2025-03-04", Some("javascript:void(0)"))
        ));
        let parsed = parse_html(&html).unwrap();
        assert_eq!(parsed.title, "新闻中心-北航");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].title, "通知一");
        assert_eq!(parsed.entries[0].date, "2026-09-20");
        assert_eq!(
            parsed.entries[0].resolved_http_url.as_deref(),
            Some("https://www.buaa.edu.cn/xwzx/2026/01.htm")
        );
        assert_eq!(parsed.entries[0].link_kind, "http");
        assert_eq!(parsed.entries[1].title, "通知二");
        assert_eq!(parsed.entries[1].date, "2025-03-04");
        assert_eq!(parsed.entries[1].link_kind, "non_http");
        assert_eq!(parsed.entries[1].resolved_http_url, None);
    }

    #[test]
    fn rejects_unformatted_listing_and_date() {
        assert!(parse_html(b"<html><body></body></html>").is_err());
        assert!(parse_html(&fixture_html("")).is_err());
        assert!(parse_html(&fixture_html(&li("x", "2026/09/20", None))).is_err());
        assert!(parse_html(&fixture_html(&li("x", "20-09-20", None))).is_err());
        assert!(parse_html(&fixture_html(&li("x", "2026-13-01", None))).is_err());
    }

    #[test]
    fn missing_anchor_or_date_rejected() {
        let html = fixture_html(&li("", "2026-09-20", Some("a.htm")));
        assert!(parse_html(&html).is_err());
    }

    #[test]
    fn oversized_and_empty_documents_rejected() {
        assert!(parse_html(&vec![0u8; MAX_HTML + 1]).is_err());
        assert!(parse_html(&[]).is_err());
    }

    #[test]
    fn parse_failures_carry_source_location_and_report_hint() {
        let err = parse_html(&fixture_html(&li(
            "x",
            "2026/09/20",
            Some("xwzx/2026/x.htm"),
        )))
        .unwrap_err();
        assert_eq!(err.code, "unavailable");
        let src = err.source.expect("parse rejections must carry file/line");
        assert_eq!(src.file, "src/announcements.rs");
        assert!(src.line > 0);
        assert!(src.invariant.contains("yyyy-mm-dd"));
        assert!(err.message.contains("github.com/cyjin-yl/buaa-cli/issues"));
        assert!(err.message.contains("page layout likely changed"));
    }

    #[test]
    fn history_parse_reuses_same_parser_without_network() {
        let bytes = fixture_html(&li("旧闻", "2003-12-01", Some("xwzx/2003/12/1.htm")));
        let parsed = history_parse(&bytes).unwrap();
        assert_eq!(parsed["entries"][0]["title"], "旧闻");
        assert_eq!(parsed["entries"][0]["date"], "2003-12-01");
        assert_eq!(
            parsed["completeness"]["scope"],
            "single_supplied_archive_snapshot"
        );
        assert!(parsed["retrieval"].is_null());
        assert!(history_parse(b"").is_err());
    }

    #[test]
    fn list_offline_denied_without_cache() {
        let err = list(CacheMode::Offline).unwrap_err();
        assert_eq!(err.code, "offline_miss");
    }
}

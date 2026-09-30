//! Official BUAA news-center (`news.buaa.edu.cn`) announcements and news, parsed
//! over a cache-first snapshot shared with the official-directory governor policy.
//!
//! The retired `www.buaa.edu.cn/xwzx.htm` listing now 404s; the live news center
//! is `news.buaa.edu.cn`. Category listings (`tzgg.htm`, `zhxw.htm`, ...) expose
//! one `.tlist li` row per item: an `a[href]` anchor, a `.pub_date` day + month,
//! and a `.pub_info` category label / `h3` title / summary `p`. Article pages
//! (`/info/<category>/<id>.htm`) carry the title in `h2`, the publish date in
//! `.cont-tit`, and the body in `.v_news_content`. Rows missing a title are
//! rejected rather than reconstructed; missing dates stay `null`. Attachment
//! links are surfaced as hints and never downloaded. Historical bytes remain
//! operator-asserted provenance, bound by SHA-256.

use crate::net::{ArchiveClient, CacheMode, Error, Response, SCSE_NOTICES_URL, SCSE_ROOT_URL};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{NaiveDate, NaiveDateTime};
use scraper::{ElementRef, Html, Node, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

mod scse;

const NEWS_BASE: &str = "https://news.buaa.edu.cn";
const MAX_HTML: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
const MAX_TEXT: usize = 512;
const MAX_HREF: usize = 4096;
const MAX_BODY_PARAGRAPHS: usize = 512;
const MAX_PARAGRAPH: usize = 8 * 1024;
const MAX_ATTACHMENT_HINTS: usize = 32;
const DEFAULT_CATEGORY: &str = "tzgg";

/// Reviewed news-center category listings as `(slug, label)` pairs.
const CATEGORIES: &[(&str, &str)] = &[
    ("tzgg", "通知公告"),
    ("zhxw", "综合新闻"),
    ("ztxw", "专题新闻"),
    ("bhrw", "北航人物"),
    ("xyfc_new", "校园风采"),
    ("kjzx_new", "科教在线"),
    ("mtbh_new", "媒体北航"),
    ("gybh_new", "光影北航"),
    ("spxw1", "视频新闻"),
    ("wyyd_new", "文艺园地"),
];

/// File extensions treated as downloadable attachments (surfaced as hints only).
const DOCUMENT_EXTENSIONS: &[&str] = &[
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".txt", ".wps",
    ".ofd",
];

#[derive(Debug, serde::Serialize)]
pub struct ListingEntry {
    pub source_order: usize,
    pub title: String,
    pub date: Option<String>,
    pub category_label: Option<String>,
    pub summary: Option<String>,
    pub listed_href: Option<String>,
    pub resolved_http_url: Option<String>,
    pub link_kind: &'static str,
}

#[derive(Debug, serde::Serialize)]
pub struct ListingDocument {
    pub title: String,
    pub entries: Vec<ListingEntry>,
}

#[derive(Debug)]
struct ArticleDocument {
    title: String,
    category: Option<String>,
    published_at: Option<String>,
    paragraphs: Vec<String>,
    attachment_hints: Vec<Value>,
    attachments_found: bool,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    college: Option<String>,
    category: Option<String>,
    page: Option<u32>,
    since: Option<String>,
    until: Option<String>,
    #[serde(rename = "match")]
    r#match: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ArticleQuery {
    url: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryInput {
    html: String,
    provenance: HistoryProvenance,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryProvenance {
    source_url: String,
    #[serde(default)]
    capture_timestamp: Option<String>,
    #[serde(default)]
    asserted_by: Option<String>,
}

fn unavailable() -> Error {
    Error::new(
        "unavailable",
        "official news-center document could not be interpreted safely; file an issue at https://github.com/cyjin-yl/buaa-cli/issues/new with this CLI version and URL",
    )
}

fn invalid_list() -> Error {
    Error::new(
        "invalid_input",
        "announcements list input is malformed; expected a JSON object with optional category, page, since, until, match",
    )
}

fn invalid_article() -> Error {
    Error::new(
        "invalid_input",
        "announcements article input is malformed; expected a JSON object with url set to a news.buaa.edu.cn /info/<category>/<id>.htm path",
    )
}

fn invalid_history() -> Error {
    Error::new(
        "invalid_input",
        "announcements history input is malformed; html must be base64 UTF-8 and provenance.source_url must be a news.buaa.edu.cn listing URL",
    )
}

/// Emit a rejected-parse error anchored to a declared invariant, so an
/// operator-agent can file a GitHub issue or debug-and-patch the listed
/// invariant and open a PR.
fn failed_contract(invariant: &'static str, file: &'static str, line: u32) -> Error {
    Error::with_source(
        "unavailable",
        "official news-center document contract violated; the public page layout likely changed. File an issue at https://github.com/cyjin-yl/buaa-cli/issues/new or debug the reported invariant yourself and open a PR",
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

/// Linear DOM walk with no ancestor rescans or subtree copies. Script/style,
/// template and noscript payloads are not source prose.
fn element_text(element: ElementRef<'_>) -> String {
    if element.ancestors().any(|node| {
        node.value()
            .as_element()
            .is_some_and(|node| matches!(node.name(), "script" | "style" | "template" | "noscript"))
    }) {
        return String::new();
    }
    let root = element.id();
    let mut current = element.first_child();
    let mut output = String::new();
    while let Some(node) = current {
        let skip = node.value().as_element().is_some_and(|node| {
            matches!(node.name(), "script" | "style" | "template" | "noscript")
        });
        if let Node::Text(text) = node.value() {
            for word in text.text.split_whitespace() {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(word);
            }
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
    output
}

fn category_label(slug: &str) -> Option<&'static str> {
    CATEGORIES
        .iter()
        .find(|(entry_slug, _)| *entry_slug == slug)
        .map(|(_, label)| *label)
}

fn is_http(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
}

/// Only the latest listing has a stable URL. Numbered pages must be selected
/// from the source's advertised links, not guessed from an ordinal.
fn latest_listing_url(category: &str) -> Result<Url, Error> {
    if category_label(category).is_none() {
        return Err(Error::new(
            "invalid_input",
            "unknown announcements category; expected one of: tzgg, zhxw, ztxw, bhrw, xyfc_new, kjzx_new, mtbh_new, gybh_new, spxw1, wyyd_new",
        ));
    }
    Url::parse(&format!("{NEWS_BASE}/{category}.htm")).map_err(|_| unavailable())
}

fn advertised_page_url(
    bytes: &[u8],
    base: &Url,
    page: u32,
    allowed_page: impl Fn(&Url) -> bool,
) -> Result<Url, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);
    let selector =
        Selector::parse("div.pb_sys_common span.p_no a[href]").map_err(|_| unavailable())?;
    for link in document.select(&selector) {
        if normalized_text(link.text()).parse::<u32>().ok() != Some(page) {
            continue;
        }
        let url = base
            .join(link.value().attr("href").ok_or_else(unavailable)?)
            .map_err(|_| unavailable())?;
        if !allowed_page(&url) {
            return Err(failed_contract(
                "advertised listing page must remain in the selected category",
                file!(),
                line!(),
            ));
        }
        return Ok(url);
    }
    Err(Error::new(
        "unavailable",
        "requested page is not advertised by the latest listing; no URL was inferred",
    ))
}

/// True when an operator-asserted history `source_url` is a news-center listing.
fn is_list_source_url(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "https"
        || url.host_str() != Some("news.buaa.edu.cn")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return false;
    }
    let path = url.path();
    CATEGORIES.iter().any(|(slug, _)| {
        path == format!("/{slug}.htm")
            || path
                .strip_prefix(&format!("/{slug}/"))
                .and_then(|tail| tail.strip_suffix(".htm"))
                .is_some_and(|page| !page.is_empty() && page.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Compact listing date `<b>DD</b><span>YYYY.MM</span>` → canonical `YYYY-MM-DD`.
fn parse_compact_date(day_raw: &str, yearmonth_raw: &str) -> Option<String> {
    let day_raw = day_raw.trim();
    let ym = yearmonth_raw.trim();
    if day_raw.is_empty() || day_raw.len() > 2 || day_raw.bytes().any(|b| !b.is_ascii_digit()) {
        return None;
    }
    if ym.len() != 7 || !ym.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let year: i32 = ym[0..4].parse().ok()?;
    if ym.as_bytes()[4] != b'.' {
        return None;
    }
    let month: u32 = ym[5..7].parse().ok()?;
    let day: u32 = day_raw.parse().ok()?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    Some(date.format("%Y-%m-%d").to_string())
}

/// Canonical ISO date filter value (`YYYY-MM-DD`), validated as a real date.
fn parse_iso_date(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() != 10 {
        return None;
    }
    let b = raw.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || !b[0..4].iter().all(|c| c.is_ascii_digit())
        || !b[5..7].iter().all(|c| c.is_ascii_digit())
        || !b[8..10].iter().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let year: i32 = raw[0..4].parse().ok()?;
    let month: u32 = raw[5..7].parse().ok()?;
    let day: u32 = raw[8..10].parse().ok()?;
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    Some(date.format("%Y-%m-%d").to_string())
}

/// Parse one news-center category listing. Public for offline evidence
/// validation; performs no network or cache access.
pub fn parse_listing(bytes: &[u8], base: &Url) -> Result<ListingDocument, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);
    let title = document
        .select(&Selector::parse("title").map_err(|_| unavailable())?)
        .next()
        .map(|node| normalized_text(node.text()))
        .unwrap_or_default();

    let row_selector = Selector::parse("div.tlist li").map_err(|_| unavailable())?;
    let anchor_selector = Selector::parse("a").map_err(|_| unavailable())?;
    let row_title_selector = Selector::parse("div.pub_info h3").map_err(|_| unavailable())?;
    let label_selector = Selector::parse("div.pub_info span").map_err(|_| unavailable())?;
    let summary_selector = Selector::parse("div.pub_info p").map_err(|_| unavailable())?;
    let day_selector = Selector::parse("div.pub_date b").map_err(|_| unavailable())?;
    let month_selector = Selector::parse("div.pub_date span").map_err(|_| unavailable())?;

    let mut entries: Vec<ListingEntry> = Vec::new();
    for row in document.select(&row_selector) {
        if entries.len() >= MAX_ENTRIES {
            return Err(failed_contract(
                "listing exceeds the reviewed entry budget",
                file!(),
                line!(),
            ));
        }
        let listed_href = row
            .select(&anchor_selector)
            .next()
            .and_then(|anchor| anchor.value().attr("href"));
        if listed_href.is_some_and(|href| href.len() > MAX_HREF) {
            return Err(failed_contract(
                "listing href exceeds the reviewed byte budget",
                file!(),
                line!(),
            ));
        }
        let listed_href = listed_href
            .filter(|href| !href.is_empty())
            .map(str::to_owned);

        let title = row
            .select(&row_title_selector)
            .next()
            .map(|node| normalized_text(node.text()))
            .filter(|t| !t.is_empty() && t.len() <= MAX_TEXT);
        let title = match title {
            Some(title) => title,
            None => {
                return Err(failed_contract(
                    "listing row must contain a non-empty pub_info h3 title",
                    file!(),
                    line!(),
                ));
            }
        };

        let category_label = row
            .select(&label_selector)
            .next()
            .map(|node| normalized_text(node.text()))
            .filter(|t| !t.is_empty() && t.len() <= MAX_TEXT);

        let summary = row
            .select(&summary_selector)
            .next()
            .map(|node| normalized_text(node.text()))
            .filter(|t| !t.is_empty())
            .map(|t| t.chars().take(MAX_TEXT).collect());

        let date = row.select(&day_selector).next().and_then(|node| {
            let day = normalized_text(node.text());
            let month = row
                .select(&month_selector)
                .next()
                .map(|node| normalized_text(node.text()))?;
            parse_compact_date(&day, &month)
        });

        let (resolved_http_url, link_kind) = match listed_href.as_deref() {
            None => (None, "missing"),
            Some(raw) => match base.join(raw) {
                Ok(resolved) if is_http(&resolved) => (Some(resolved.to_string()), "http"),
                Ok(_) => (None, "non_http"),
                Err(_) => (None, "invalid"),
            },
        };

        entries.push(ListingEntry {
            source_order: entries.len() + 1,
            title,
            date,
            category_label,
            summary,
            listed_href,
            resolved_http_url,
            link_kind,
        });
    }
    if entries.is_empty() {
        return Err(failed_contract(
            "listing must contain at least one div.tlist li row",
            file!(),
            line!(),
        ));
    }
    Ok(ListingDocument { title, entries })
}

fn parse_article(bytes: &[u8], url: &Url) -> Result<ArticleDocument, Error> {
    if bytes.is_empty() || bytes.len() > MAX_HTML {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let document = Html::parse_document(text);

    let title = document
        .select(&Selector::parse("h2").map_err(|_| unavailable())?)
        .next()
        .map(|node| normalized_text(node.text()))
        .filter(|t| !t.is_empty() && t.len() <= MAX_HREF);
    let title = match title {
        Some(title) => title,
        None => {
            return Err(failed_contract(
                "article must contain a non-empty h2 title",
                file!(),
                line!(),
            ));
        }
    };

    let published_at = document
        .select(&Selector::parse("div.cont-tit p").map_err(|_| unavailable())?)
        .next()
        .and_then(|node| {
            let text = normalized_text(node.text());
            let tokens: Vec<&str> = text.split_whitespace().collect();
            tokens
                .iter()
                .position(|token| token.contains("发布时间"))
                .and_then(|index| tokens.get(index + 1))
                .map(|token| token.to_string())
        })
        .and_then(|raw| parse_iso_date(&raw));

    let body_selector = Selector::parse("div.v_news_content p").map_err(|_| unavailable())?;
    let mut paragraphs: Vec<String> = Vec::new();
    for paragraph in document.select(&body_selector) {
        let text = element_text(paragraph);
        if text.is_empty() {
            continue;
        }
        if paragraphs.len() >= MAX_BODY_PARAGRAPHS {
            return Err(failed_contract(
                "article body exceeds the reviewed paragraph budget",
                file!(),
                line!(),
            ));
        }
        if text.len() > MAX_PARAGRAPH {
            return Err(failed_contract(
                "article paragraph exceeds the reviewed byte budget",
                file!(),
                line!(),
            ));
        }
        paragraphs.push(text);
    }
    if paragraphs.is_empty() {
        return Err(failed_contract(
            "article must contain at least one v_news_content paragraph",
            file!(),
            line!(),
        ));
    }

    let link_selector = Selector::parse("div.v_news_content a[href]").map_err(|_| unavailable())?;
    let mut attachment_hints: Vec<Value> = Vec::new();
    let mut attachments_found = false;
    for anchor in document.select(&link_selector) {
        let Some(href) = anchor.value().attr("href") else {
            continue;
        };
        if !is_document_href(href) {
            continue;
        }
        attachments_found = true;
        if attachment_hints.len() < MAX_ATTACHMENT_HINTS {
            attachment_hints.push(json!({
                "href": href,
                "text": normalized_text(anchor.text()),
            }));
        }
    }

    Ok(ArticleDocument {
        title,
        category: article_category_from_url(url),
        published_at,
        paragraphs,
        attachment_hints,
        attachments_found,
    })
}

fn article_category_from_url(url: &Url) -> Option<String> {
    let segments = url.path_segments()?.collect::<Vec<_>>();
    if segments.first() == Some(&"info") && segments.len() == 3 {
        Some(segments[1].to_string())
    } else {
        None
    }
}

fn is_document_href(href: &str) -> bool {
    let path = href.split(['?', '#']).next().unwrap_or(href);
    let lower = path.to_ascii_lowercase();
    DOCUMENT_EXTENSIONS
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn retrieval(response: &Response) -> Value {
    json!({
        "source_url": response.url,
        "fetched_at_unix_ms": response.fetched_at_unix_ms,
        "cache_status": response.cache_status,
        "response_body_sha256": response.sha256,
        "response_body_byte_length": response.body.len(),
        "revalidated_at_unix_ms": response.revalidated_at_unix_ms,
        "revalidation_status": response.revalidation_status,
        "http": {"status": response.status, "headers": response.headers},
    })
}

fn entry_in_scope(
    entry: &ListingEntry,
    since: &Option<String>,
    until: &Option<String>,
    match_substring: &Option<String>,
) -> bool {
    if match_substring
        .as_deref()
        .is_some_and(|pattern| !pattern.is_empty() && !entry.title.contains(pattern))
    {
        return false;
    }
    if let Some(since) = since {
        match &entry.date {
            Some(date) if date.as_str() >= since.as_str() => {}
            _ => return false,
        }
    }
    if let Some(until) = until {
        match &entry.date {
            Some(date) if date.as_str() <= until.as_str() => {}
            _ => return false,
        }
    }
    true
}

fn normalize_listing(
    response: &Response,
    category: &str,
    page: u32,
    since: &Option<String>,
    until: &Option<String>,
    match_substring: &Option<String>,
) -> Result<Value, Error> {
    let url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let document = parse_listing(&response.body, &url)?;
    let entries: Vec<&ListingEntry> = document
        .entries
        .iter()
        .filter(|entry| entry_in_scope(entry, since, until, match_substring))
        .collect();
    let listing_label = category_label(category).unwrap_or_default();
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_list",
        "result": "listing_snapshot",
        "publisher": "北京航空航天大学",
        "listing_label": listing_label,
        "category": category,
        "page": page,
        "filters": {
            "since": since,
            "until": until,
            "match": match_substring,
        },
        "document_title": document.title,
        "entry_count": entries.len(),
        "entries": entries,
        "completeness": {
            "scope": format!("category_{category}_page_{page}"),
            "pagination": "explicit_page_selected_from_advertised_links; no automatic traversal",
            "date_filter_semantics": "entries without a parseable date are dropped when since or until is set",
            "historical_content": "use_buaa_archive",
        },
        "retrieval": retrieval(response),
    }))
}

fn normalize_article(response: &Response) -> Result<Value, Error> {
    let url = Url::parse(&response.url).map_err(|_| unavailable())?;
    let document = parse_article(&response.body, &url)?;
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_article",
        "result": "full_text",
        "publisher": "北京航空航天大学",
        "title": document.title,
        "category": document.category,
        "published_at": document.published_at,
        "body_paragraph_count": document.paragraphs.len(),
        "body_paragraphs": document.paragraphs,
        "attachments": {
            "found": document.attachments_found,
            "hints": document.attachment_hints,
            "note": "attachment links are surfaced as hints and are never downloaded by this command",
        },
        "completeness": {
            "scope": "single_article_page",
            "body_source": "div.v_news_content p",
        },
        "retrieval": retrieval(response),
    }))
}

fn parse_list_query(input: Option<&str>) -> Result<ListQuery, Error> {
    match input {
        None => Ok(ListQuery::default()),
        Some(raw) if raw.trim().is_empty() => Ok(ListQuery::default()),
        Some(raw) => serde_json::from_str::<Option<ListQuery>>(raw)
            .map(Option::unwrap_or_default)
            .map_err(|_| invalid_list()),
    }
}

pub fn list(mode: CacheMode, input: Option<&str>) -> Result<Value, Error> {
    let query = parse_list_query(input)?;
    match query.college.as_deref() {
        Some("scse") => return scse::list(mode, &query),
        Some(_) => return Err(invalid_list()),
        None => {}
    }
    let category = query.category.as_deref().unwrap_or(DEFAULT_CATEGORY);
    let page = query.page.unwrap_or(1);
    if page < 1 {
        return Err(invalid_list());
    }
    let since = match query.since.as_deref() {
        Some(raw) => Some(parse_iso_date(raw).ok_or_else(invalid_list)?),
        None => None,
    };
    let until = match query.until.as_deref() {
        Some(raw) => Some(parse_iso_date(raw).ok_or_else(invalid_list)?),
        None => None,
    };
    let latest = latest_listing_url(category)?;
    // Page discovery is always cache-first; --refresh applies to the selected
    // page, not to the latest-listing snapshot used for ordinal resolution.
    let discovery_mode = if mode == CacheMode::Revalidate {
        CacheMode::PreferCache
    } else {
        mode
    };
    let discovery_client = ArchiveClient::open_announcements(discovery_mode)?;
    let url = if page == 1 {
        latest
    } else {
        let prefix = format!("/{category}/");
        discovery_client.get(&latest, false, |response| {
            advertised_page_url(&response.body, &latest, page, |url| {
                is_list_source_url(url.as_str()) && url.path().starts_with(&prefix)
            })
        })?
    };
    let client = discovery_client.with_cache_mode(mode);
    client.get(&url, false, move |response| {
        normalize_listing(response, category, page, &since, &until, &query.r#match)
    })
}

fn resolve_article_url(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| invalid_article())?;
    if url.scheme() != "https"
        || url.host_str() != Some("news.buaa.edu.cn")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(invalid_article());
    }
    let segments = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let valid = segments.len() == 3
        && segments[0] == "info"
        && !segments[1].is_empty()
        && segments[1].len() <= 10
        && segments[1].bytes().all(|b| b.is_ascii_digit())
        && segments[2].strip_suffix(".htm").is_some_and(|stem| {
            !stem.is_empty() && stem.len() <= 10 && stem.bytes().all(|b| b.is_ascii_digit())
        });
    if !valid {
        return Err(invalid_article());
    }
    Ok(url)
}

pub fn article(mode: CacheMode, input: &str) -> Result<Value, Error> {
    let query: ArticleQuery = serde_json::from_str(input).map_err(|_| invalid_article())?;
    let raw_url = query
        .url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
        .ok_or_else(invalid_article)?;
    if Url::parse(raw_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .as_deref()
        == Some("scse.buaa.edu.cn")
    {
        return scse::article(mode, raw_url);
    }
    let url = resolve_article_url(raw_url)?;
    let client = ArchiveClient::open_announcements(mode)?;
    client.get(&url, false, normalize_article)
}

/// Fixed public college pages, not a unified college crawler or a verified
/// announcement parser. Never follows the returned hints.
pub fn scse_surface(mode: CacheMode, page: &str) -> Result<Value, Error> {
    let raw = match page {
        "root" => SCSE_ROOT_URL,
        "notices" => SCSE_NOTICES_URL,
        _ => return Err(Error::new("invalid_input", "unknown college surface page")),
    };
    let url = Url::parse(raw).map_err(|_| unavailable())?;
    let client = ArchiveClient::open_scse(mode)?;
    client.get(&url, false, describe_scse_surface)
}

fn describe_scse_surface(response: &Response) -> Result<Value, Error> {
    if response.status != 200 || response.body.len() > MAX_HTML {
        return Err(unavailable());
    }
    let input = std::str::from_utf8(&response.body).map_err(|_| unavailable())?;
    let document = Html::parse_document(input);
    let title_selector = Selector::parse("title").map_err(|_| unavailable())?;
    let title = document
        .select(&title_selector)
        .next()
        .map(|node| normalized_text(node.text()))
        .filter(|title| !title.is_empty());
    if title.as_ref().is_some_and(|title| title.len() > MAX_TEXT) {
        return Err(unavailable());
    }
    let anchor_selector = Selector::parse("a[href]").map_err(|_| unavailable())?;
    let base = Url::parse(&response.url).map_err(|_| unavailable())?;
    let mut hints = Vec::new();
    let mut hints_truncated = false;
    for node in document.select(&anchor_selector) {
        let raw = node.value().attr("href").unwrap_or_default();
        if raw.len() > MAX_HREF {
            continue;
        }
        let Ok(url) = base.join(raw) else {
            continue;
        };
        if !is_http(&url)
            || url.host_str() != Some("scse.buaa.edu.cn")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
        {
            continue;
        }
        let label = normalized_text(node.text());
        if label.is_empty() || label.len() > MAX_TEXT {
            continue;
        }
        if hints.len() == 64 {
            hints_truncated = true;
            break;
        }
        hints.push(json!({"path":url.path(),"listed_scheme":url.scheme(),"label":label}));
    }
    Ok(json!({
        "schema_version":1,"type":"college_source_surface","result":"surface_snapshot",
        "college":"computer_science",
        "directory_attribution":{"name":"计算机学院","listed_href":"http://scse.buaa.edu.cn/","note":"the directory href is preserved; this command explicitly observes HTTPS separately"},
        "document_title":title,"same_host_path_hints":hints,"hints_truncated":hints_truncated,
        "completeness":{"scope":"single_explicit_public_page","announcement_adapter_verified":false,"links_followed":false,"publication_date":"unknown"},
        "retrieval":retrieval(response),
    }))
}

pub fn history(input: &str) -> Result<Value, Error> {
    if input.len() > MAX_HTML.div_ceil(3) * 4 + 128 {
        return Err(invalid_history());
    }
    let query: HistoryInput = serde_json::from_str(input).map_err(|_| invalid_history())?;
    let college_snapshot = scse::is_history_source(&query.provenance.source_url);
    if !college_snapshot && !is_list_source_url(&query.provenance.source_url) {
        return Err(invalid_history());
    }
    let timestamp = match &query.provenance.capture_timestamp {
        Some(value) => Some(
            capture_timestamp(value)
                .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .map_err(|_| invalid_history()),
        )
        .transpose()?,
        None => None,
    };
    let bytes = STANDARD
        .decode(query.html.as_bytes())
        .map_err(|_| invalid_history())?;
    if bytes.len() > MAX_HTML {
        return Err(invalid_history());
    }
    let base = Url::parse(&query.provenance.source_url).map_err(|_| invalid_history())?;
    let document = if college_snapshot {
        scse::parse_listing(&bytes, &base)
    } else {
        parse_listing(&bytes, &base)
    }
    .map_err(|_| invalid_history())?;
    let hash = format!("{:x}", Sha256::digest(&bytes));
    Ok(json!({
        "schema_version": 1,
        "type": "announcements_history",
        "result": "listing_snapshot",
        "publisher": if college_snapshot {scse::PUBLISHER} else {"北京航空航天大学"},
        "college": if college_snapshot {Some("scse")} else {None},
        "listing_label": "新闻中心（历史快照）",
        "document_title": document.title,
        "entries": document.entries,
        "provenance": {
            "status": "operator_asserted",
            "source_url": query.provenance.source_url,
            "capture_timestamp": timestamp,
            "asserted_by": query.provenance.asserted_by,
            "verification": "asserted_only; archive response headers were not supplied with the bytes",
        },
        "completeness": {
            "scope": "single_supplied_archive_snapshot",
            "pagination": "not_applicable",
            "freshness": "archived_bytes",
        },
        "retrieval": {
            "sha256": hash,
            "supplied_bytes": bytes.len(),
            "provenance_status": "operator_asserted",
        },
    }))
}

fn capture_timestamp(value: &str) -> Result<NaiveDateTime, ()> {
    if value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let part =
        |range: std::ops::Range<usize>| -> Result<u32, ()> { value[range].parse().map_err(|_| ()) };
    let year = part(0..4)? as i32;
    let date = NaiveDate::from_ymd_opt(year, part(4..6)?, part(6..8)?).ok_or(())?;
    date.and_hms_opt(part(8..10)?, part(10..12)?, part(12..14)?)
        .ok_or(())
}

pub fn schema() -> Value {
    let news_categories: Vec<Value> = CATEGORIES
        .iter()
        .map(|(slug, _)| json!(slug))
        .chain(std::iter::once(Value::Null))
        .collect();
    json!({
        "college_source": {
            "input":{"description":"announcements college-source scse [root|notices] [--online|--refresh]; fixed public pages only. No stdin or arbitrary URL."},
            "output":{"type":"object","description":"Source-contract observation with byte/hash retrieval facts and bounded same-host path hints. Hints are never followed; this is not a complete college crawl."}
        },
        "list": {
            "input": {
                "type": ["object", "null"],
                "description": "Optional JSON object. Without college: university news center, default category tzgg. college=scse selects the separately verified computer-college notices source, category gggs. Page defaults to 1; later ordinals must be advertised by the selected source. since/until are inclusive dates, match is a title substring. No automatic crawl or inferred page URLs.",
                "additionalProperties": false,
                "properties": {
                    "college": {"enum": ["scse",null]},
                    "category": {"type": ["string","null"]},
                    "page": {"type": ["integer","null"], "minimum": 1,"maximum":u32::MAX},
                    "since": {"type": ["string","null"], "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                    "until": {"type": ["string","null"], "pattern": "^\\d{4}-\\d{2}-\\d{2}$"},
                    "match": {"type": ["string","null"]}
                },
                "allOf":[{"if":{"required":["college"],"properties":{"college":{"const":"scse"}}},
                    "then":{"properties":{"category":{"enum":["gggs",null]}}},
                    "else":{"properties":{"category":{"enum":news_categories}}}}]
            },
            "output": {
                "type": "object",
                "description": "Selected-source listing snapshot with title/date/link entries, explicit college scope when selected, filters and retrieval provenance. No all-college coverage claim.",
            }
        },
        "article": {
            "input": {
                "type": "object",
                "description": "JSON object with url: a news-center article or a reviewed scse.buaa.edu.cn notice article in category 1099/1299. HTTPS only; no query, credentials, custom port or fragment.",
                "additionalProperties":false,"required":["url"],
                "properties": {"url": {"type": "string"}}
            },
            "output": {
                "type": "object",
                "description": "Source paragraph text excluding code/fallback markup, publication facts and attachment hints. College image/PDF-preview pages explicitly return embedded_document or partial_text rather than fabricated full text; preview/attachment bytes are never fetched and OCR is not performed.",
            }
        },
        "history": {
            "input": {
                "type": "object",
                "description": "Offline operator-asserted snapshot: base64 html, provenance.source_url (a reviewed news-center or SCSE notices listing), optional capture_timestamp and asserted_by. Historical SCSE HTTP originals are preserved; no request or archive-attribution verification occurs.",
            },
            "output": {
                "type": "object",
                "description": "Parsed snapshot with asserted provenance and SHA-256 byte binding.",
            }
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing_html() -> String {
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>通知公告-新闻网</title></head><body>
<div class="tlist"><ul>
<li><a href="info/1010/69802.htm"><div class="pub_date"><div><b>15</b><span>2026.09</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>关于启动交换项目的通知</h3><p>第一段摘要</p></div></a></li>
<li><a href="info/1010/69801.htm"><div class="pub_date"><div><b>01</b><span>2026.09</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>另一条通知</h3><p>第二段摘要</p></div></a></li>
<li><a href="info/1010/69700.htm"><div class="pub_date"><div><b>26</b><span>2026.08</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>更早的通知</h3><p>第三段摘要</p></div></a></li>
</ul></div></body></html>"#
            .to_string()
    }

    fn base_url() -> Url {
        Url::parse("https://news.buaa.edu.cn/tzgg.htm").unwrap()
    }

    #[test]
    fn parse_listing_reads_tlist_rows() {
        let document = parse_listing(listing_html().as_bytes(), &base_url()).unwrap();
        assert_eq!(document.title, "通知公告-新闻网");
        assert_eq!(document.entries.len(), 3);
        let first = &document.entries[0];
        assert_eq!(first.title, "关于启动交换项目的通知");
        assert_eq!(first.date.as_deref(), Some("2026-09-15"));
        assert_eq!(first.category_label.as_deref(), Some("通知公告"));
        assert_eq!(first.summary.as_deref(), Some("第一段摘要"));
        assert_eq!(first.link_kind, "http");
        assert_eq!(
            first.resolved_http_url.as_deref(),
            Some("https://news.buaa.edu.cn/info/1010/69802.htm")
        );
        assert_eq!(document.entries[2].date.as_deref(), Some("2026-08-26"));
    }

    #[test]
    fn parse_listing_reports_missing_link_kind() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body>
<div class="tlist"><ul><li><div class="pub_date"><div><b>01</b><span>2026.09</span></div></div>
<div class="pub_info"><span>通知公告</span><h3>无链接</h3><p>摘要</p></div></li></ul></div></body></html>"#;
        let document = parse_listing(html.as_bytes(), &base_url()).unwrap();
        assert_eq!(document.entries[0].link_kind, "missing");
        assert!(document.entries[0].listed_href.is_none());
    }

    #[test]
    fn parse_listing_rejects_row_without_title() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body>
<div class="tlist"><ul><li><a href="info/1010/1.htm"><div class="pub_info"><span>通知公告</span><p>无标题</p></div></a></li></ul></div></body></html>"#;
        let err = parse_listing(html.as_bytes(), &base_url()).unwrap_err();
        assert_eq!(err.code, "unavailable");
        let src = err.source.expect("parse rejections must carry file/line");
        assert_eq!(src.file, "src/announcements.rs");
    }

    #[test]
    fn parse_listing_rejects_empty_list() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body><div class="tlist"><ul></ul></div></body></html>"#;
        assert!(parse_listing(html.as_bytes(), &base_url()).is_err());
    }

    #[test]
    fn present_over_budget_links_are_rejected_not_reported_missing() {
        let body = listing_html().replace("info/1010/69802.htm", &"x".repeat(MAX_HREF + 1));
        assert_eq!(
            parse_listing(body.as_bytes(), &base_url())
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn iso_filter_rejects_signed_years_instead_of_widening_query_scope() {
        assert_eq!(parse_iso_date("-001-01-01"), None);
    }

    #[test]
    fn compact_date_is_normalized_and_validated() {
        assert_eq!(
            parse_compact_date("15", "2026.09"),
            Some("2026-09-15".to_string())
        );
        assert_eq!(parse_compact_date("15", "2026.9"), None);
        assert_eq!(parse_compact_date("32", "2026.09"), None);
        assert_eq!(parse_compact_date("15", "2026.13"), None);
        assert_eq!(parse_compact_date("", "2026.09"), None);
    }

    #[test]
    fn iso_date_filter_is_validated() {
        assert_eq!(parse_iso_date("2026-09-15"), Some("2026-09-15".to_string()));
        assert_eq!(parse_iso_date("2026-13-01"), None);
        assert_eq!(parse_iso_date("2026-09-32"), None);
        assert_eq!(parse_iso_date("2026/09/15"), None);
    }

    #[test]
    fn pagination_uses_advertised_ordinals_not_filename_numbers() {
        let html = br#"<div class="pb_sys_common"><span class="p_no"><a href="tzgg/252.htm">2</a></span><span class="p_no"><a href="tzgg/1.htm">253</a></span></div>"#;
        let base = latest_listing_url("tzgg").unwrap();
        let allowed =
            |url: &Url| is_list_source_url(url.as_str()) && url.path().starts_with("/tzgg/");
        assert_eq!(
            advertised_page_url(html, &base, 2, allowed).unwrap().path(),
            "/tzgg/252.htm"
        );
        assert_eq!(
            advertised_page_url(html, &base, 253, allowed)
                .unwrap()
                .path(),
            "/tzgg/1.htm"
        );
        assert_eq!(
            advertised_page_url(html, &base, 6, allowed)
                .unwrap_err()
                .code,
            "unavailable"
        );
        let foreign = br#"<div class="pb_sys_common"><span class="p_no"><a href="https://evil.example/tzgg/252.htm">2</a></span></div>"#;
        assert_eq!(
            advertised_page_url(foreign, &base, 2, allowed)
                .unwrap_err()
                .code,
            "unavailable"
        );
    }

    #[test]
    fn entry_scope_applies_filters() {
        let document = parse_listing(listing_html().as_bytes(), &base_url()).unwrap();
        let since = Some("2026-09-01".to_string());
        let none = None;
        let in_scope: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &since, &none, &none))
            .collect();
        assert_eq!(in_scope.len(), 2);
        let match_sub = Some("交换".to_string());
        let matched: Vec<&ListingEntry> = document
            .entries
            .iter()
            .filter(|entry| entry_in_scope(entry, &none, &none, &match_sub))
            .collect();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].title, "关于启动交换项目的通知");
    }

    #[test]
    fn parse_article_extracts_body_date_and_attachments() {
        let html = r#"<!DOCTYPE html><html><head><title>关于启动交换项目的通知</title></head><body>
<h2>关于启动交换项目的通知</h2>
<div class="cont-tit"><p>发布时间: 2026-09-15 / 点击数: 100</p></div>
<div class="v_news_content">
<p>第一段正文。</p>
<p>第二段正文。</p>
<p><a href="files/报名须知.pdf">报名须知</a></p>
</div></body></html>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/69802.htm").unwrap();
        let document = parse_article(html.as_bytes(), &url).unwrap();
        assert_eq!(document.title, "关于启动交换项目的通知");
        assert_eq!(document.category.as_deref(), Some("1010"));
        assert_eq!(document.published_at.as_deref(), Some("2026-09-15"));
        assert_eq!(document.paragraphs.len(), 3);
        assert!(document.attachments_found);
        assert_eq!(document.attachment_hints.len(), 1);
        assert_eq!(document.attachment_hints[0]["href"], "files/报名须知.pdf");
    }

    #[test]
    fn parse_article_rejects_missing_body() {
        let html = r#"<!DOCTYPE html><html><head><title>t</title></head><body><h2>标题</h2><div class="v_news_content"></div></body></html>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/1.htm").unwrap();
        assert!(parse_article(html.as_bytes(), &url).is_err());
    }

    #[test]
    fn executable_or_fallback_markup_is_not_article_text() {
        let html = r#"<title>Fixture</title><h2>Fixture title</h2><div class="v_news_content"><p><script>var embedded_document = ["not policy text"];</script><style>.hidden { display:none }</style><noscript>Enable JavaScript</noscript></p></div>"#;
        let url = Url::parse("https://news.buaa.edu.cn/info/1010/1.htm").unwrap();
        assert_eq!(
            parse_article(html.as_bytes(), &url).unwrap_err().code,
            "unavailable"
        );
    }

    #[test]
    fn resolve_article_url_rejects_foreign_paths() {
        assert!(resolve_article_url("https://news.buaa.edu.cn/info/1010/69802.htm").is_ok());
        assert!(resolve_article_url("https://evil.example/info/1010/1.htm").is_err());
        assert!(resolve_article_url("https://news.buaa.edu.cn/info/1010/1.htm?x=1").is_err());
        assert!(resolve_article_url("https://news.buaa.edu.cn/xwzx.htm").is_err());
        assert!(resolve_article_url("https://news.buaa.edu.cn/info/abc/1.htm").is_err());
    }

    #[test]
    fn history_requires_operator_asserted_provenance() {
        let html = listing_html();
        let encoded = STANDARD.encode(html.as_bytes());
        let input = json!({
            "html": encoded,
            "provenance": {
                "source_url": "https://news.buaa.edu.cn/tzgg.htm",
                "capture_timestamp": "20260920120000"
            }
        })
        .to_string();
        let output = history(&input).unwrap();
        assert_eq!(output["provenance"]["status"], "operator_asserted");
        assert_eq!(
            output["provenance"]["source_url"],
            "https://news.buaa.edu.cn/tzgg.htm"
        );
        assert_eq!(
            output["provenance"]["capture_timestamp"],
            "2026-09-20T12:00:00Z"
        );
        assert_eq!(output["entries"].as_array().unwrap().len(), 3);
        assert_eq!(output["retrieval"]["sha256"].as_str().unwrap().len(), 64);

        let foreign = json!({
            "html": encoded,
            "provenance": {"source_url": "https://www.buaa.edu.cn/xwzx.htm"}
        })
        .to_string();
        let err = history(&foreign).unwrap_err();
        assert_eq!(err.code, "invalid_input");

        let article_url = json!({
            "html": encoded,
            "provenance": {"source_url": "https://news.buaa.edu.cn/info/1010/1.htm"}
        })
        .to_string();
        assert!(history(&article_url).is_err());
    }

    #[test]
    fn history_accepts_paged_sources_without_relaxing_provenance_scope() {
        let mut input = json!({
            "html": STANDARD.encode(listing_html().replace("href=\"info/", "href=\"../info/")),
            "provenance": {
                "source_url": "https://news.buaa.edu.cn/tzgg/252.htm",
                "asserted_by": "fixture-operator"
            }
        });
        let result = history(&input.to_string()).unwrap();
        assert_eq!(
            result["provenance"]["source_url"],
            input["provenance"]["source_url"]
        );
        assert_eq!(result["provenance"]["asserted_by"], "fixture-operator");
        assert_eq!(result["provenance"]["status"], "operator_asserted");
        assert_eq!(
            result["entries"][0]["resolved_http_url"],
            "https://news.buaa.edu.cn/info/1010/69802.htm"
        );
        for source in [
            "https://news.buaa.edu.cn/tzgg/.htm",
            "https://news.buaa.edu.cn/tzgg/2.52.htm",
            "https://news.buaa.edu.cn/tzgg/252.htm#fragment",
            "https://operator:secret@news.buaa.edu.cn/tzgg.htm",
            "https://news.buaa.edu.cn:8443/tzgg.htm",
        ] {
            input["provenance"]["source_url"] = json!(source);
            assert_eq!(
                history(&input.to_string()).unwrap_err().code,
                "invalid_input"
            );
        }
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static OFFLINE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    /// Hermetic offline contract: an empty cache directory must yield
    /// `offline_miss` for both listing and article URLs, without touching the
    /// operator's real cache, governor, or network.
    #[test]
    fn offline_lookup_with_empty_cache_reports_unavailable() {
        let root = std::env::temp_dir().join(format!(
            "buaa-announcements-offline-{}-{}",
            std::process::id(),
            OFFLINE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let client =
            ArchiveClient::open_announcements_offline_for_test(&root.join("cache")).unwrap();
        let listing = client
            .get(&latest_listing_url("tzgg").unwrap(), false, |_| Ok(()))
            .unwrap_err();
        assert_eq!(listing.code, "offline_miss");
        let article = client
            .get(
                &resolve_article_url("https://news.buaa.edu.cn/info/1010/1.htm").unwrap(),
                false,
                |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(article.code, "offline_miss");
        assert!(!root.join("cache/governor").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
